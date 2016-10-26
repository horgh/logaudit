/*
 * This program is to make examining log files on an Ubuntu GNU/Linux server
 * simpler.
 *
 * My use case is I admin a server and want to keep an eye on the logs. There
 * are many log messages I don't really care about. I don't need to see
 * everything.
 *
 * This program will examine all log files in /var/log. It will report any it
 * does not know about so they can be supported. It will look at each log file
 * it knows about and trim out all log messages that I do not care to see. It
 * will then show only the useful ones. It does this using regular expressions.
 *
 * I hope this to make monitoring the logs more efficient for me.
 *
 * I am sure there are other solutions out there to do things like this.
 * However I want fine grained control and to know deeply about what logs I
 * watch and what messages I see or do not see. I think creating my own will
 * make this possible.
 */

package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Args holds the command line arguments.
type Args struct {
	// LogDir is the directory where the logs are. Typically /var/log.
	LogDir string

	// ConfigFile is the file describing the logs to look at.
	ConfigFile string

	// ShowIgnoredOnly is a flag to do the inverse of usual operations. I figure
	// it may be useful to see what the program excludes for some double checking.
	ShowIgnoredOnly bool

	// Location is the time zone location.
	Location *time.Location

	// FilterStartTime sets the time to bound log lines. Log lines to show must
	// be on or after this time.
	FilterStartTime time.Time
}

// LogConfig is a block read from the config file. It describes what to do with
// a set of logs.
type LogConfig struct {
	// A glob style file pattern. It should be relative to the LogDir.
	// e.g., auth.log*
	FilenamePattern string

	// FullyIgnore means the log will not be read at all. Some logs are not useful
	// to look at line by line. e.g., binary type logs.
	FullyIgnore bool

	// IncludeAllIgnorePatterns causes log patterns from every LogConfig to be
	// used when examining the matched log. This is because some logs have lines
	// from other logs (syslog for instance).
	IncludeAllIgnorePatterns bool

	// TimeLayout is a time layout format. See the Constants section on the
	// Go time package page.
	TimeLayout string

	// IgnorePatterns holds the regular expressions that we apply to determine
	// whether a log line should be ignored or not.
	IgnorePatterns []*regexp.Regexp
}

// LogLine holds information about a single log line.
type LogLine struct {
	// Path to its log.
	Log string

	// The line itself.
	Line string

	// Its timestamp.
	Time time.Time
}

// ByTime is provides sorting LogLines by time.
type ByTime []LogLine

func (s ByTime) Less(i, j int) bool { return s[i].Time.Before(s[j].Time) }
func (s ByTime) Len() int           { return len(s) }
func (s ByTime) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func main() {
	// Turn down log output prefix verbosity.
	log.SetFlags(0)

	args, err := getArgs()
	if err != nil {
		log.Fatalf("Invalid argument: %s", err.Error())
	}

	config, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err.Error())
	}

	logFiles, err := findLogFiles(args.LogDir)
	if err != nil {
		log.Fatalf("Unable to find log files: %s", err.Error())
	}

	// Examine each log file one by one and output any relevant entries.
	err = auditLogs(args.LogDir, logFiles, config, args.ShowIgnoredOnly,
		args.Location, args.FilterStartTime)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err.Error())
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	logDir := flag.String("log-dir", "/var/log", "Path to directory containing logs.")
	config := flag.String("config", "", "Path to the configuration file. See logs.conf.sample for an example.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines. Note this won't show lines from files that are configured as fully ignored.")
	locationString := flag.String("location", "America/Vancouver", "Timezone location. IANA Time Zone database name.")
	filterStartTimeString := flag.String("filter-start-time", "1999-12-31", "Filter log lines to those on or after the given timestamp. Format: YYYY-MM-DD HH:MM:SS or YYYY-MM-DD.")

	flag.Parse()

	if len(*logDir) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a log directory.")
	}
	fi, err := os.Lstat(*logDir)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid log directory: %s", err.Error())
	}
	if !fi.IsDir() {
		return Args{}, fmt.Errorf("Invalid log directory: %s: Not a directory.",
			*logDir)
	}

	if len(*config) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a config file.")
	}
	fi, err = os.Lstat(*config)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid config file: %s", err.Error())
	}
	if !fi.Mode().IsRegular() {
		return Args{}, fmt.Errorf("Invalid config file: %s: Not a regular file.",
			*config)
	}

	if len(*locationString) == 0 {
		return Args{}, fmt.Errorf("Please provide a time zone location.")
	}
	location, err := time.LoadLocation(*locationString)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid location: %s", err.Error())
	}

	if len(*filterStartTimeString) == 0 {
		return Args{}, fmt.Errorf("Please provide a filter start time.")
	}
	filterStartTime, err := time.ParseInLocation("2006-01-02 15:04:05",
		*filterStartTimeString, location)
	if err != nil {
		filterStartTime, err = time.ParseInLocation("2006-01-02",
			*filterStartTimeString, location)
		if err != nil {
			return Args{}, fmt.Errorf("Invalid filter start time (%s): %s. Please use format YYYY-MM-DD HH:MM:SS or YYYY-MM-DD.", *filterStartTimeString, err.Error())
		}
	}

	return Args{
		LogDir:          *logDir,
		ConfigFile:      *config,
		ShowIgnoredOnly: *showIgnored,
		Location:        location,
		FilterStartTime: filterStartTime,
	}, nil
}

// parseConfig reads the config file into memory.
//
// The config is made up of blocks that start with a FilenamePattern and
// look like the following. Note all except FilenamePattern are optional.
//
// FilenamePattern: path/filepath pattern
//   e.g. /var/log/auth.log*
//
// FullyIgnore: y or n
//   To ignore the file completely
//
// IncludeAllIgnorePatterns: y or n
//   This causes all other log patterns to be included when ignoring lines in
//   the log. This is useful for logs that have lines that are also in other
//   lines, such as /var/log/syslog.
//
// TimeLayout: Time layout string
//   This allows you to specify the timestamp format of the log. It must be
//   at the beginning of the log line. The format for this string is the same
//   as Go's time layout.
//   If you don't specify this, the default is time.Stamp.
//
// Ignore: regexp
//   A regexp applied to each line. If it matches, the line gets ignored.
//
// We ignore blank lines and # comments.
func parseConfig(configFile string) ([]LogConfig, error) {
	fh, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", configFile, err.Error())
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	var configs []LogConfig

	var config LogConfig

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 ||
			strings.HasPrefix(text, "#") {
			continue
		}

		nameRe := regexp.MustCompile("^FilenamePattern: (.+)")
		matches := nameRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern != "" {
				if config.TimeLayout == "" {
					config.TimeLayout = time.Stamp
				}
				configs = append(configs, config)
			}
			config = LogConfig{FilenamePattern: matches[1]}
			continue
		}

		fullyIgnoreRe := regexp.MustCompile("^FullyIgnore: (y|n)$")
		matches = fullyIgnoreRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			config.FullyIgnore = matches[1] == "y"
			continue
		}

		includeAllRe := regexp.MustCompile("^IncludeAllIgnorePatterns: (y|n)$")
		matches = includeAllRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			config.IncludeAllIgnorePatterns = matches[1] == "y"
			continue
		}

		timeLayoutRe := regexp.MustCompile("^TimeLayout: (.+)")
		matches = timeLayoutRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			config.TimeLayout = matches[1]
			continue
		}

		patternRe := regexp.MustCompile("^Ignore: (.+)")
		matches = patternRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			config.IgnorePatterns = append(config.IgnorePatterns,
				regexp.MustCompile(matches[1]))
			continue
		}

		return nil, fmt.Errorf("Unexpected line: %s", text)
	}

	// Ensure we store the last config block we were reading.
	if config.FilenamePattern != "" {
		if config.TimeLayout == "" {
			config.TimeLayout = time.Stamp
		}
		configs = append(configs, config)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("Scanner: %s", err.Error())
	}

	return configs, nil
}

// findLogFiles will return a list of files under /var/log. The paths to each.
func findLogFiles(root string) ([]string, error) {
	fh, err := os.Open(root)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", root, err.Error())
	}

	// I don't defer close here. I'm recursively descending and want to close
	// at the earliest possible point instead of waiting until we all return.

	fi, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("Stat: %s: %s", root, err.Error())
	}

	if !fi.IsDir() {
		_ = fh.Close()
		return nil, fmt.Errorf("Root is not a directory: %s", root)
	}

	files, err := fh.Readdirnames(0)
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("Readdirnames: %s: %s", root, err.Error())
	}

	err = fh.Close()
	if err != nil {
		return nil, fmt.Errorf("fh.Close: %s", err)
	}

	// Check each file in the directory.
	// If it is a file, record it. If it is a directory, descend into it.

	var logFiles []string

	for _, filename := range files {
		path := fmt.Sprintf("%s%c%s", root, os.PathSeparator, filename)

		fi2, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("Lstat: %s: %s", path, err.Error())
		}

		if fi2.Mode().IsDir() {
			dirFiles, err := findLogFiles(path)
			if err != nil {
				return nil, err
			}

			logFiles = append(logFiles, dirFiles...)
			continue
		}

		if !fi2.Mode().IsRegular() {
			return nil, fmt.Errorf("Not a regular file: %s", path)
		}

		logFiles = append(logFiles, path)
	}

	sort.Strings(logFiles)

	return logFiles, nil
}

// auditLogs looks at each log.
//
// First, it will check by filename whether it is a log we know about. If it is
// not, then it will raise an error and abort.
//
// Then it will examine the log's contents. For some log files I do not care
// about the contents at all and we skip it entirely. For others we filter out
// for lines of interest.
func auditLogs(logDirRoot string, logFiles []string,
	logConfigs []LogConfig, showIgnoredOnly bool, location *time.Location,
	filterStartTime time.Time) error {

	// Gather all ignore patterns in one slice - we use them all at once sometimes
	// and this is handy.
	var ignorePatterns []*regexp.Regexp
	for _, logConfig := range logConfigs {
		ignorePatterns = append(ignorePatterns, logConfig.IgnorePatterns...)
	}

	// Gather log lines together.
	// Key by the log pattern so we group related lines of logs together.
	logToLines := make(map[string][]LogLine)

	for _, logFile := range logFiles {
		err := auditLog(logToLines, logDirRoot, logFile, logConfigs, ignorePatterns,
			showIgnoredOnly, location, filterStartTime)
		if err != nil {
			return fmt.Errorf("auditLog: %s", err.Error())
		}
	}

	// Sort keys (log patterns) first.
	logKeys := []string{}
	for k := range logToLines {
		logKeys = append(logKeys, k)
	}

	sort.Strings(logKeys)

	for _, logKey := range logKeys {
		// Sort lines by time. This is because we've gathered them from logs in
		// order of their file names which is not representative of the actual
		// log entry time.
		sort.Sort(ByTime(logToLines[logKey]))

		for _, line := range logToLines[logKey] {
			log.Printf("%s: %s", line.Log, line.Line)
		}
	}

	return nil
}

// auditLog examines a single log file.
//
// It looks for it being a match of a configured log. If it's not, then
// this is an error. All log files should be recognized.
//
// It then decides what to do with its contents. Either the contents are
// fully ignored, or patterns are applied line by line to decide whether
// to exclude them from displaying or not.
func auditLog(logToLines map[string][]LogLine, logDirRoot string, logFile string,
	logConfigs []LogConfig, allIgnorePatterns []*regexp.Regexp,
	showIgnoredOnly bool, location *time.Location,
	filterStartTime time.Time) error {
	for _, logConfig := range logConfigs {
		match, err := fileMatch(logDirRoot, logFile, logConfig.FilenamePattern)
		if err != nil {
			return fmt.Errorf("fileMatch: %s: %s", logFile, err.Error())
		}

		if !match {
			continue
		}

		if logConfig.FullyIgnore {
			return nil
		}

		var ignorePatterns []*regexp.Regexp

		if logConfig.IncludeAllIgnorePatterns {
			ignorePatterns = allIgnorePatterns
		} else {
			ignorePatterns = logConfig.IgnorePatterns
		}

		logLines, err := filterLogLines(logFile, ignorePatterns, showIgnoredOnly,
			location, logConfig.TimeLayout, filterStartTime)
		if err != nil {
			return fmt.Errorf("filterLogLines: %s: %s", logFile, err.Error())
		}

		_, ok := logToLines[logConfig.FilenamePattern]
		if !ok {
			logToLines[logConfig.FilenamePattern] = []LogLine{}
		}
		logToLines[logConfig.FilenamePattern] = append(
			logToLines[logConfig.FilenamePattern], logLines...)

		return nil
	}

	return fmt.Errorf("Unrecognized file: %s", logFile)
}

// fileMatch takes a root directory, the actual path to the log file, and a
// path pattern that should be a subdirectory under the root. It decides
// if the root plus the subdirectory pattern match the log file.
//
// The pattern is a filepath.Match() pattern.
func fileMatch(logDirRoot string, logFile string, path string) (bool, error) {
	pattern := fmt.Sprintf("%s%c%s", logDirRoot, os.PathSeparator, path)
	match, err := filepath.Match(pattern, logFile)
	if err != nil {
		return false, fmt.Errorf("filepath.Match: %s: %s: %s", pattern, logFile,
			err.Error())
	}
	return match, nil
}

// fileLogLines opens the log file and reads line by line.
// If the line matches an ignore pattern, then we don't log the line.
// Otherwise we log it.
func filterLogLines(path string, ignoreRegexps []*regexp.Regexp,
	showIgnoredOnly bool, location *time.Location,
	timeLayout string, filterStartTime time.Time) ([]LogLine, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", path, err.Error())
	}

	defer fh.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %s: %s", path, err.Error())
		}
		defer gz.Close()

		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(fh)
	}

	// Track the last time we were able to parse a line's time in this log.
	// Why? Because some logs don't have a timestamp on every line but we can
	// apply a prior line's time as useful to a later line.
	// e.g., samba log lines are split over multiple lines, and apt/history.log
	// has multi line entries.
	var lastLineTime time.Time
	var zeroTime time.Time

	var logLines []LogLine

LineLoop:
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 ||
			scanner.Text() == "(Nothing has been logged yet.)" {
			continue
		}

		// Parse its time, if possible.
		lineTime, err := parseLineTime(text, location, timeLayout)
		if err != nil {
			if lastLineTime == zeroTime {
				log.Printf("Line's time could not be determined: %s: %s", text,
					err.Error())
			} else {
				lineTime = lastLineTime
			}
		} else {
			lastLineTime = lineTime
		}

		// Filter first. Don't include anything filtered in the "show ignored"
		// basket. I'll call the ignore patterns something separate from filters.
		if lineTime.Before(filterStartTime) {
			continue
		}

		// Does it match one of our ignore patterns?
		for _, re := range ignoreRegexps {
			if re.MatchString(text) {
				if showIgnoredOnly {
					logLines = append(logLines, LogLine{
						Log:  path,
						Line: text,
						Time: lineTime,
					})
				}
				continue LineLoop
			}
		}

		if !showIgnoredOnly {
			logLines = append(logLines, LogLine{
				Log:  path,
				Line: text,
				Time: lineTime,
			})
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("Scanner: %s", err.Error())
	}

	return logLines, nil
}

// parseLineTime attempts to parse the timestamp from the log line.
func parseLineTime(line string, location *time.Location,
	timeLayout string) (time.Time, error) {
	// ParseInLocation does not like there to be extra text. It wants only the
	// timestamp portion to be present. Let's try to strip off only the timestamp.

	// I do this by counting how many spaces are in the layout, and then trying
	// to copy from the line until we have the same number of spaces copied.

	var lastChar rune

	lineStamp := ""
	for _, c := range line {
		if c == ' ' {
			// Stop when we have as many space blocks as the layout.
			// Ensure we don't mistake a new block for the current one by checking
			// the last character we saw.
			if countCharBlocksInString(lineStamp, ' ') ==
				countCharBlocksInString(timeLayout, ' ') &&
				lastChar != ' ' {
				break
			}
		}

		lineStamp += string(c)
		lastChar = c
	}

	lineTime, err := time.ParseInLocation(timeLayout, lineStamp, location)
	if err != nil {
		return time.Time{}, fmt.Errorf("Could not parse [%s] with layout [%s]: %s",
			lineStamp, timeLayout, err.Error())
	}

	// Unspecified fields become zero. Like year for time layouts.
	// Put zero years in the current year. Yes, this is invalid when we roll
	// over in December/January if we're not careful.
	if lineTime.Year() == 0 {
		// Assumption: If it is January and the line we see is in December, then
		// it is in the current year - 1. Otherwise, put the line in the current
		// year.
		year := time.Now().Year()
		if time.Now().Month() == time.January && lineTime.Month() == time.December {
			year = time.Now().Year() - 1
		}

		lineTime = lineTime.AddDate(year, 0, 0)
	}

	return lineTime, nil
}

// countCharBlocksInString counts how many parts of a string consist of
// 1 or more of a character. e.g., "ab c" has 1, and so does "ab  c".
func countCharBlocksInString(s string, c rune) int {
	count := 0

	var last rune

	for _, b := range s {
		if b == c {
			if last == c {
				continue
			}
			count++
		}
		last = b
	}

	return count
}
