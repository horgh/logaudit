//
// This program is to make examining log files on GNU/Linux machines simpler
// (Debian/Ubuntu with syslog, specifically).
//
// I have a few machines and I want to keep an eye on the logs. One problem is
// that there are many log messages I don't really care about. Another is that
// it is time consuming to go and look at each log file on each host.
//
// This program examines all log files in /var/log. It outputs all of the log
// lines at once. You can configure it to ignore certain files all together, or
// to ignore lines with regexes.
//
// I hope this to make monitoring the logs more efficient for me.
//
// I know there are other solutions out there to do things like this (such as
// logwatch). However I want fine grained control and to know deeply about what
// logs I watch and what messages I see or do not see.
//
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
	"strconv"
	"strings"
	"time"
)

// Args holds the command line arguments.
type Args struct {
	// LogDir is the directory where the logs are. Typically /var/log.
	LogDir string

	// ConfigFile is the file describing the logs to look at.
	ConfigFile string

	// StateFile is a file we record our starting runtime in. We can look at this
	// file as a way to base when to filter logs starting from.
	StateFile string

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
	// Go time package page. We use it to parse timestamps on log lines.
	TimeLayout string

	// Decide how to get timestamp from a log.
	// Ideally we will have a timestamp on each log line. However this is not
	// always the case. For some logs there is a timestamp on some lines but
	// not others. Likely there are logs where there is no timestamp available.
	TimestampStrategy TimestampStrategy

	// IgnorePatterns holds the regular expressions that we apply to determine
	// whether a log line should be ignored or not.
	IgnorePatterns []*regexp.Regexp
}

// TimestampStrategy specifies a strategy for gathering a line's timestamp.
type TimestampStrategy int

const (
	// EveryLine means require each line to have a valid timestamp.
	EveryLine TimestampStrategy = iota

	// LastLine means to use the timestamp from the last line we parsed with
	// a valid timestamp. This is useful for logs that have timestamps on some
	// lines but not others. It means we assign a log line the timestamp of the
	// last log line that had a timestamp.
	LastLine

	// LastLineOrStat means to apply the log file's modified time to any lines
	// without a timestamp if they occur prior to seeing a line with a timestamp.
	// It's a more relaxed version of LastLine.
	LastLineOrStat
)

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
		log.Fatalf("Invalid argument: %s", err)
	}

	config, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err)
	}

	runStartTime := time.Now()

	logFiles, err := findLogFiles(args.LogDir)
	if err != nil {
		log.Fatalf("Unable to find log files: %s", err)
	}

	// Examine each log file one by one and output any relevant entries.
	err = auditLogs(args.LogDir, logFiles, config, args.ShowIgnoredOnly,
		args.Location, args.FilterStartTime)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err)
	}

	if len(args.StateFile) > 0 {
		err = writeStateFile(args.StateFile, runStartTime)
		if err != nil {
			log.Fatalf("Problem writing state file: %s: %s", args.StateFile, err)
		}
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	logDir := flag.String("log-dir", "/var/log", "Path to directory containing logs.")
	config := flag.String("config", "", "Path to the configuration file. See logs.conf.sample for an example.")
	stateFile := flag.String("state-file", "", "Path to the state file. Run start time gets recorded here (if success), and we filter log lines to those after the run time if the file is present when we start. Note the filter start time argument overrides this.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines. Note this won't show lines from files that are configured as fully ignored.")
	locationString := flag.String("location", "America/Vancouver", "Timezone location. IANA Time Zone database name.")
	filterStartTimeString := flag.String("filter-start-time", "", "Filter log lines to those on or after the given timestamp. Format: YYYY-MM-DD HH:MM:SS or YYYY-MM-DD.")

	flag.Parse()

	if len(*logDir) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a log directory.")
	}
	fi, err := os.Stat(*logDir)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid log directory: %s", err)
	}
	if !fi.IsDir() {
		return Args{}, fmt.Errorf("Invalid log directory: %s: Not a directory.",
			*logDir)
	}

	if len(*config) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a config file.")
	}
	fi, err = os.Stat(*config)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid config file: %s", err)
	}
	if !fi.Mode().IsRegular() {
		return Args{}, fmt.Errorf("Invalid config file: %s: Not a regular file.",
			*config)
	}

	var filterStartTime time.Time

	// State file is optional.
	if len(*stateFile) > 0 {
		// It may not exist, and that's okay. It could be our first run.
		_, err := os.Stat(*stateFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return Args{}, fmt.Errorf("Unable to read state file: %s", err)
			}
		} else {
			stateFileTime, err := readStateFileTime(*stateFile)
			if err != nil {
				return Args{}, fmt.Errorf("Unable to read state file: %s", err)
			}
			// To account for buffered writes, use an hour before the state file time
			// (which should be when the last run started).
			filterStartTime = stateFileTime.Add(-time.Hour)
		}
	}

	if len(*locationString) == 0 {
		return Args{}, fmt.Errorf("Please provide a time zone location.")
	}
	location, err := time.LoadLocation(*locationString)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid location: %s", err)
	}

	if len(*filterStartTimeString) > 0 {
		filterStartTime, err = time.ParseInLocation("2006-01-02 15:04:05",
			*filterStartTimeString, location)
		if err != nil {
			filterStartTime, err = time.ParseInLocation("2006-01-02",
				*filterStartTimeString, location)
			if err != nil {
				return Args{}, fmt.Errorf("Invalid filter start time (%s): %s. Please use format YYYY-MM-DD HH:MM:SS or YYYY-MM-DD.", *filterStartTimeString, err)
			}
		}
	}

	return Args{
		LogDir:          *logDir,
		ConfigFile:      *config,
		StateFile:       *stateFile,
		ShowIgnoredOnly: *showIgnored,
		Location:        location,
		FilterStartTime: filterStartTime,
	}, nil
}

// Read a state file. It should contain a single value, a unixtime. Parse it and
// return.
func readStateFileTime(path string) (time.Time, error) {
	fh, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	for scanner.Scan() {
		unixtime, err := strconv.ParseInt(scanner.Text(), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("Malformed time in state file: %s: %s",
				scanner.Text(), err)
		}
		return time.Unix(unixtime, 0), nil
	}

	err = scanner.Err()
	if err != nil {
		return time.Time{}, fmt.Errorf("Scanner: %s", err)
	}

	return time.Time{}, fmt.Errorf("State file had no content")
}

// Write the given time to the state file.
// The state file has no content other than a unixtime.
func writeStateFile(path string, startTime time.Time) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}

	unixtime := fmt.Sprintf("%d", startTime.Unix())

	n, err := fh.WriteString(unixtime)
	if err != nil {
		_ = fh.Close()
		return err
	}

	if n != len(unixtime) {
		_ = fh.Close()
		return fmt.Errorf("Short write")
	}

	err = fh.Close()
	if err != nil {
		return fmt.Errorf("Close error: %s", err)
	}

	return nil
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
// TimestampStrategy: The method to use to extract timestamps for each log line.
//   This can currently be "every-line", which means to require a valid
//   timestamp on each line, or "last-line", which means that some lines in a
//   log have timestamps, and to apply the timestamp from the last line in the
//   file that had a timestamp to any lines following it without a timestamp.
//   It may also be "last-line-or-stat" which means to use the file's modified
//   time if there was no line parsed yet with a timestamp, but to use the log's
//   last line timestamp if there was one seen. This is useful if there is a log
//   that has a line which starts with a line that doesn't have a timestamp yet
//   some lines do have timestamps.
//
// Ignore: regexp
//   A regexp applied to each line. If it matches, the line gets ignored.
//
// We ignore blank lines and # comments.
func parseConfig(configFile string) ([]LogConfig, error) {
	fh, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", configFile, err)
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
				configs = append(configs, config)
			}
			config = LogConfig{
				FilenamePattern:   matches[1],
				TimeLayout:        time.Stamp,
				TimestampStrategy: EveryLine,
				IgnorePatterns:    []*regexp.Regexp{},
			}
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

		strategyRe := regexp.MustCompile("^TimestampStrategy: (.+)")
		matches = strategyRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			if matches[1] == "every-line" {
				config.TimestampStrategy = EveryLine
			} else if matches[1] == "last-line" {
				config.TimestampStrategy = LastLine
			} else if matches[1] == "last-line-or-stat" {
				config.TimestampStrategy = LastLineOrStat
			} else {
				return nil, fmt.Errorf("Invalid timestamp strategy: %s", matches[1])
			}
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
		return nil, fmt.Errorf("Scanner: %s", err)
	}

	return configs, nil
}

// findLogFiles will return a list of files under /var/log. The paths to each.
func findLogFiles(root string) ([]string, error) {
	fh, err := os.Open(root)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", root, err)
	}

	// I don't defer close here. I'm recursively descending and want to close
	// at the earliest possible point instead of waiting until we all return.

	fi, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("Stat: %s: %s", root, err)
	}

	if !fi.IsDir() {
		_ = fh.Close()
		return nil, fmt.Errorf("Root is not a directory: %s", root)
	}

	files, err := fh.Readdirnames(0)
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("Readdirnames: %s: %s", root, err)
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

		fi2, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("Stat: %s: %s", path, err)
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
			return fmt.Errorf("auditLog: %s", err)
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

// Look at each log config. If it matches the log file, return it. We return the
// first one that matches.
func getConfigForLogFile(logDirRoot, logFile string,
	logConfigs []LogConfig) (LogConfig, bool, error) {
	for _, logConfig := range logConfigs {
		match, err := fileMatch(logDirRoot, logFile, logConfig.FilenamePattern)
		if err != nil {
			return LogConfig{}, false, fmt.Errorf("fileMatch: %s: %s", logFile,
				err)
		}

		if match {
			return logConfig, true, nil
		}
	}
	return LogConfig{}, false, nil
}

// auditLog examines a single log file.
//
// It looks for it being a match of a configured log. If it's not, then
// this is an error. All log files should be recognized.
//
// It then decides what to do with its contents. Either the contents are
// fully ignored, or patterns are applied line by line to decide whether
// to exclude them from displaying or not.
func auditLog(logToLines map[string][]LogLine, logDirRoot, logFile string,
	logConfigs []LogConfig, allIgnorePatterns []*regexp.Regexp,
	showIgnoredOnly bool, location *time.Location,
	filterStartTime time.Time) error {

	// Skip it if it's modified time is before our start time.
	fi, err := os.Stat(logFile)
	if err != nil {
		return fmt.Errorf("Stat: %s: %s", logFile, err)
	}
	if fi.ModTime().Before(filterStartTime) {
		return nil
	}

	logConfig, match, err := getConfigForLogFile(logDirRoot, logFile,
		logConfigs)
	if err != nil {
		return fmt.Errorf("Unable to determine config for log file: %s: %s",
			logFile, err)
	}
	if !match {
		log.Printf("Log %s did not match any configuration. Dumping it entirely.",
			logFile)
		lines, err := readLog(logFile)
		if err != nil {
			return err
		}
		for _, line := range lines {
			log.Printf("%s: %s", logFile, line)
		}
		return nil
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
		location, logConfig.TimeLayout, logConfig.TimestampStrategy,
		filterStartTime)
	if err != nil {
		return fmt.Errorf("filterLogLines: %s: %s", logFile, err)
	}

	_, ok := logToLines[logConfig.FilenamePattern]
	if !ok {
		logToLines[logConfig.FilenamePattern] = []LogLine{}
	}
	logToLines[logConfig.FilenamePattern] = append(
		logToLines[logConfig.FilenamePattern], logLines...)

	return nil
}

// fileMatch takes a root directory, the actual path to the log file, and a
// path pattern that should be a subdirectory under the root. It decides if the
// root plus the subdirectory pattern match the log file.
//
// The pattern is a filepath.Match() pattern.
func fileMatch(logDirRoot string, logFile string, path string) (bool, error) {
	pattern := fmt.Sprintf("%s%c%s", logDirRoot, os.PathSeparator, path)
	match, err := filepath.Match(pattern, logFile)
	if err != nil {
		return false, fmt.Errorf("filepath.Match: %s: %s: %s", pattern, logFile,
			err)
	}
	return match, nil
}

// fileLogLines opens the log file and reads line by line.
// If the line matches an ignore pattern, then we don't log the line.
// Otherwise we log it.
func filterLogLines(path string, ignoreRegexps []*regexp.Regexp,
	showIgnoredOnly bool, location *time.Location,
	timeLayout string, timestampStrategy TimestampStrategy,
	filterStartTime time.Time) ([]LogLine, error) {

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("Stat: %s: %s", path, err)
	}

	lines, err := readLog(path)
	if err != nil {
		return nil, err
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
	for _, text := range lines {
		// Parse its time, if possible.
		lineTime, err := parseLineTime(text, location, timeLayout)
		if err != nil {
			if timestampStrategy == EveryLine {
				return nil, fmt.Errorf("Line's time could not be determined: %s: %s", text,
					err)
			}
			if timestampStrategy == LastLine {
				// We've not yet seen any timestamp. This is a problem. We want to apply
				// the timestamp from the last log line that had one.
				if lastLineTime == zeroTime {
					return nil, fmt.Errorf("Line's time could not be determined: %s: %s", text,
						err)
				}
				lineTime = lastLineTime
			}
			if timestampStrategy == LastLineOrStat {
				if lastLineTime == zeroTime {
					lineTime = fi.ModTime()
				} else {
					lineTime = lastLineTime
				}
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

	return logLines, nil
}

// Read all log lines into memory.
func readLog(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Open: %s: %s", path, err)
	}

	defer fh.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %s: %s", path, err)
		}
		defer gz.Close()

		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(fh)
	}

	// Increase default buffer size. I ran into max token errors in
	// apt/history.log.
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, cap(buf))

	lines := []string{}

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 ||
			scanner.Text() == "(Nothing has been logged yet.)" {
			continue
		}
		lines = append(lines, text)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("Scanner: %s", err)
	}

	return lines, nil
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
		return time.Time{}, fmt.Errorf("Could not parse line's timestamp: %s: %s",
			lineStamp, err)
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
