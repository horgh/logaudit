// This program ships logs from the server it runs on.
//
// It reads logs from /var/log, skips those with a timestamp prior to its last
// run, filters them, and ships the remainder by publishing them to a GCP
// Pub/Sub topic.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"

	"github.com/pkg/errors"
)

// Args holds the command line arguments.
type Args struct {
	// Verbose output.
	Verbose bool

	// ConfigFile is the file describing the logs to look at.
	ConfigFile string

	email string

	// StateFile is a file we record our starting runtime in. We can look at this
	// file as a way to base when to filter logs starting from.
	StateFile string

	// Location is our time zone location.
	Location *time.Location

	projectID string
	topic     string
}

// LogConfig is a block read from the config file. It describes what to do with
// a set of logs.
type LogConfig struct {
	// A glob style file pattern. It should be relative to the logDir.
	// e.g., auth.log*
	FilenamePattern string

	// FullyIgnore means the log will not be read at all. Some logs are not useful
	// to look at line by line. e.g., binary type logs.
	FullyIgnore bool

	// IncludeAllIgnorePatterns causes log patterns from every LogConfig to be
	// used when examining the matched log. This is because some logs have lines
	// from other logs (syslog for instance).
	IncludeAllIgnorePatterns bool

	// IgnorePatterns holds the regular expressions that we apply to determine
	// whether a log line should be ignored or not.
	IgnorePatterns []*regexp.Regexp

	// TimeRegexp is a regex to extract the timestamp portion of the log line.
	//
	// Sometimes log lines do not have their timestamps sufficiently close to the
	// beginning of a line to do without this, or they begin with a dynamic
	// prefix. Using a regex we can extract the timestamp portion and then parse
	// it with time layouts. However, it's often possible to write a time layout
	// such that this is not necessary.
	//
	// If specified, the regex must have a single capture group. We will apply
	// TimeLayouts to what we capture.
	//
	// If not specified then we use the line as is.
	TimeRegexp *regexp.Regexp

	// TimeLayouts holds a set of time layout formats. See the Constants section
	// on the Go time package page for what a time layout is. We use them to parse
	// timestamps on log lines. We try them in order until one succeeds.
	TimeLayouts []string

	// Decide how to get timestamp from a log.
	// Ideally we will have a timestamp on each log line. However this is not
	// always the case. For some logs there is a timestamp on some lines but
	// not others. Likely there are logs where there is no timestamp available.
	TimestampStrategy TimestampStrategy
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

func main() {
	log.SetFlags(0)

	runStartTime := time.Now()

	args, err := getArgs()
	if err != nil {
		log.Printf("Invalid argument: %s", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	stateFileTime, err := readStateFileTime(args.StateFile)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	// To account for buffered writes, use an hour before the state file time
	// (which should be when the last run started).
	lastRunTime := stateFileTime.Add(-time.Hour)

	configs, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	logFiles, err := findLogFiles(logDir)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	ctx := context.Background()

	if err := readAndShipLogs(
		ctx,
		args.email,
		args.projectID,
		args.topic,
		logFiles,
		configs,
		args.Location,
		lastRunTime,
		args.Verbose,
	); err != nil {
		log.Fatalf("%+v", err)
	}

	err = writeStateFile(args.StateFile, runStartTime)
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

const logDir = "/var/log"

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	verbose := flag.Bool("verbose", false, "Enable verbose output.")

	config := flag.String("config", "", "Path to the configuration file.")
	email := flag.String("email", "", "Recipient of logs.")
	stateFile := flag.String("state-file", "", "Path to the state file. Run start time gets recorded here. We filter log lines to those after the run time if the file is present when we start.")
	locationString := flag.String("location", "America/Vancouver", "IANA Time Zone database name. We treat timestamps as being in this timezone.")

	projectID := flag.String("project-id", "", "GCP Project ID")
	topic := flag.String("topic", "", "GCP Pub/Sub topic")

	flag.Parse()

	if len(*config) == 0 {
		return Args{}, fmt.Errorf("you must provide a config file")
	}
	fi, err := os.Stat(*config)
	if err != nil {
		return Args{}, fmt.Errorf("invalid config file: %s", err)
	}
	if !fi.Mode().IsRegular() {
		return Args{}, fmt.Errorf("invalid config file: %s: not a regular file",
			*config)
	}

	if *email == "" {
		return Args{}, errors.New("you must provide an email")
	}

	if len(*stateFile) == 0 {
		return Args{}, fmt.Errorf("you must provide a state file")
	}

	if len(*locationString) == 0 {
		return Args{}, fmt.Errorf("please provide a time zone location")
	}
	location, err := time.LoadLocation(*locationString)
	if err != nil {
		return Args{}, fmt.Errorf("invalid location: %s", err)
	}

	if *projectID == "" {
		return Args{}, errors.New("project ID is required")
	}

	if *topic == "" {
		return Args{}, errors.New("topic is required")
	}

	return Args{
		Verbose:    *verbose,
		ConfigFile: *config,
		email:      *email,
		StateFile:  *stateFile,
		Location:   location,
		projectID:  *projectID,
		topic:      *topic,
	}, nil
}

// readStateFileTime reads a state file.
//
// The file should contain a single value, a unixtime. Parse it and return.
//
// If the file does not exist, return 24 hours ago. It is okay for it not to
// exist as this could be the first run.
func readStateFileTime(path string) (time.Time, error) {
	_, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return time.Time{}, fmt.Errorf("unable to stat state file: %s", err)
		}

		return time.Now().Add(-24 * time.Hour), nil
	}

	fh, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}

	defer func() {
		err := fh.Close()
		if err != nil {
			log.Printf("close: %s: %s", path, err)
		}
	}()

	scanner := bufio.NewScanner(fh)

	for scanner.Scan() {
		unixtime, err := strconv.ParseInt(scanner.Text(), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("malformed time in state file: %s: %s",
				scanner.Text(), err)
		}

		return time.Unix(unixtime, 0), nil //nolint:staticcheck
	}

	err = scanner.Err()
	if err != nil {
		return time.Time{}, fmt.Errorf("scanner: %s", err)
	}

	return time.Time{}, fmt.Errorf("state file had no content")
}

// writeStateFile writes the given time to the state file.
//
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
		return fmt.Errorf("short write")
	}

	err = fh.Close()
	if err != nil {
		return fmt.Errorf("close error: %s", err)
	}

	return nil
}

// parseConfig reads the config file into memory.
//
// The config is made up of blocks that start with a FilenamePattern and
// look like the following. Note all except FilenamePattern are optional. Each
// block is a single log file type config.
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
// Ignore: regexp
//   A regexp applied to each line. If it matches, the line gets ignored.
//
// TimeRegexp: A regex with a single capture group. Refer to LogConfig for what
//   this is.
//
// TimeLayouts: Time layout string
//   This allows you to specify the timestamp formats of the log. They must be
//   at the beginning of the log line. The format for these strings is the same
//   as Go's time layout. If you don't specify this, the default is only
//   time.Stamp.
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
// We ignore blank lines and # comments.
func parseConfig(configFile string) ([]LogConfig, error) {
	fh, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("open: %s: %s", configFile, err)
	}

	defer func() {
		err := fh.Close()
		if err != nil {
			log.Printf("Close: %s: %s", configFile, err)
		}
	}()

	scanner := bufio.NewScanner(fh)

	var configs []LogConfig
	var config LogConfig

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || strings.HasPrefix(text, "#") {
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
				TimeLayouts:       []string{time.Stamp},
				TimestampStrategy: EveryLine,
			}
			continue
		}

		fullyIgnoreRe := regexp.MustCompile("^FullyIgnore: (y|n)$")
		matches = fullyIgnoreRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("you must set FilenamePattern to start a config block")
			}
			config.FullyIgnore = matches[1] == "y"
			continue
		}

		includeAllRe := regexp.MustCompile("^IncludeAllIgnorePatterns: (y|n)$")
		matches = includeAllRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, errors.New(
					"you must set FilenamePattern to start a config block",
				)
			}
			config.IncludeAllIgnorePatterns = matches[1] == "y"
			continue
		}

		patternRe := regexp.MustCompile("^Ignore: (.+)")
		matches = patternRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, errors.New(
					"you must set FilenamePattern to start a config block",
				)
			}

			config.IgnorePatterns = append(
				config.IgnorePatterns,
				regexp.MustCompile(matches[1]),
			)
			continue
		}

		timeRegexpRe := regexp.MustCompile("^TimeRegexp: (.+)")
		if matches := timeRegexpRe.FindStringSubmatch(text); matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf(
					"you must set FilenamePattern to start a config block")
			}
			re, err := regexp.Compile(matches[1])
			if err != nil {
				return nil, fmt.Errorf("error compiling regex: %s: %s", matches[1], err)
			}
			config.TimeRegexp = re
			continue
		}

		timeLayoutRe := regexp.MustCompile("^TimeLayout: (.+)")
		matches = timeLayoutRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("you must set FilenamePattern to start a config block")
			}
			config.TimeLayouts = append(config.TimeLayouts, matches[1])
			continue
		}

		strategyRe := regexp.MustCompile("^TimestampStrategy: (.+)")
		matches = strategyRe.FindStringSubmatch(text)
		if matches != nil {
			if config.FilenamePattern == "" {
				return nil, fmt.Errorf("you must set FilenamePattern to start a config block")
			}
			if matches[1] == "every-line" {
				config.TimestampStrategy = EveryLine
			} else if matches[1] == "last-line" {
				config.TimestampStrategy = LastLine
			} else if matches[1] == "last-line-or-stat" {
				config.TimestampStrategy = LastLineOrStat
			} else {
				return nil, fmt.Errorf("invalid timestamp strategy: %s", matches[1])
			}
			continue
		}

		return nil, fmt.Errorf("unexpected line: %s", text)
	}

	// Ensure we store the last config block we were reading.
	if config.FilenamePattern != "" {
		configs = append(configs, config)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("scanner: %s", err)
	}

	return configs, nil
}

// findLogFiles will return a list of files under /var/log. The paths to each.
func findLogFiles(root string) ([]string, error) {
	fh, err := os.Open(root)
	if err != nil {
		return nil, fmt.Errorf("open: %s: %s", root, err)
	}

	// I don't defer close here. I'm recursively descending and want to close
	// at the earliest possible point instead of waiting until we all return.

	fi, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("stat: %s: %s", root, err)
	}

	if !fi.IsDir() {
		_ = fh.Close()
		return nil, fmt.Errorf("root is not a directory: %s", root)
	}

	files, err := fh.Readdirnames(0)
	if err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("readdirnames: %s: %s", root, err)
	}

	err = fh.Close()
	if err != nil {
		return nil, fmt.Errorf("close: %s", err)
	}

	// Check each file in the directory.
	// If it is a file, record it. If it is a directory, descend into it.

	var logFiles []string

	for _, filename := range files {
		path := fmt.Sprintf("%s%c%s", root, os.PathSeparator, filename)

		fi2, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat: %s: %s", path, err)
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
			return nil, fmt.Errorf("not a regular file: %s", path)
		}

		logFiles = append(logFiles, path)
	}

	sort.Strings(logFiles)

	return logFiles, nil
}

// readAndShipLogs reads in each log and ships its lines.
//
// First, try to recognize the filename. This helps us know how to determine
// log line time.
//
// Then read in the log's lines. Try to assign a timestamp to each one.
//
// Then ship them.
func readAndShipLogs(
	ctx context.Context,
	email,
	projectID,
	topic string,
	logFiles []string,
	logConfigs []LogConfig,
	location *time.Location,
	lastRunTime time.Time,
	verbose bool,
) error {
	// Gather all ignore patterns in one slice. Certain log files apply all
	// patterns at once.
	var allIgnorePatterns []*regexp.Regexp
	for _, config := range logConfigs {
		allIgnorePatterns = append(allIgnorePatterns, config.IgnorePatterns...)
	}

	var report string
	for _, logFile := range logFiles {
		config, match, err := getConfigForLogFile(logFile, logConfigs, verbose)
		if err != nil {
			return fmt.Errorf("unable to determine config for log file: %s: %s",
				logFile, err)
		}
		if !match {
			log.Printf("Log missing configuration: %s", logFile)
			continue
		}

		if config.FullyIgnore {
			continue
		}

		logLines, err := readLog(logFile, config, location, lastRunTime, verbose)
		if err != nil {
			return fmt.Errorf("unable to read log: %s: %s", logFile, err)
		}

		interestingLogLines := filterLogLines(allIgnorePatterns, config, logLines)
		if len(interestingLogLines) == 0 {
			continue
		}

		if report != "" {
			report += "\n\n"
		}
		report += "Logs in " + logFile + ":\n"
		for _, line := range interestingLogLines {
			report += line.Line + "\n"
		}
	}

	if err := ship(ctx, email, projectID, topic, report); err != nil {
		return errors.WithMessage(err, "error shipping logs")
	}

	return nil
}

// Look at each log config. If it matches the log file, return it. We return the
// first one that matches.
func getConfigForLogFile(
	file string,
	configs []LogConfig,
	verbose bool,
) (LogConfig, bool, error) {
	for _, config := range configs {
		match, err := fileMatch(logDir, file, config.FilenamePattern)
		if err != nil {
			return LogConfig{}, false, fmt.Errorf("fileMatch: %s: %s", file, err)
		}

		if match {
			if verbose {
				fmt.Printf("Matched file: %s to: %+v\n", file, config)
			}
			return config, true, nil
		}
	}
	return LogConfig{}, false, nil
}

// fileMatch takes a root directory, the actual path to the log file, and a
// path pattern that should be a subdirectory under the root. It decides if the
// root plus the subdirectory pattern match the log file.
//
// The pattern is a filepath.Match() pattern.
func fileMatch(root string, path string, subdirPattern string) (bool, error) {
	pattern := fmt.Sprintf("%s%c%s", root, os.PathSeparator, subdirPattern)
	match, err := filepath.Match(pattern, path)
	if err != nil {
		return false, fmt.Errorf("filepath.Match: %s: %s: %s", pattern, path, err)
	}
	return match, nil
}

// readLog reads a single log file.
//
// Try to assign a timestamp to each log line.
//
// Skip any that are before the last run time.
func readLog(
	file string,
	config LogConfig,
	location *time.Location,
	lastRunTime time.Time,
	verbose bool,
) ([]*logLine, error) {
	if verbose {
		fmt.Printf("Looking at log %s...\n", file)
	}

	// Skip it if its modified time is before our start time.
	fi, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("stat: %s: %s", file, err)
	}
	if fi.ModTime().Before(lastRunTime) {
		if verbose {
			fmt.Printf("Skipping log %s (last modified before our last run time)\n",
				file)
		}
		return nil, nil
	}

	lines, err := readFileAsLines(file)
	if err != nil {
		return nil, err
	}

	err = assignTimeToLines(lines, config, location, fi.ModTime())
	if err != nil {
		return nil, err
	}

	// Pull out lines after our last run time.
	newLines := []*logLine{}
	for i, line := range lines {
		if line.Time.Before(lastRunTime) {
			continue
		}
		// We expect all lines after it are after in time as well.
		if i+1 < len(lines) {
			newLines = append(newLines, lines[i+1:]...)
		}
		break
	}

	return newLines, nil
}

type logLine struct {
	// Host that had the line. This is not always populated.
	Hostname string

	// Path to its log.
	Log string

	// The line itself.
	Line string

	// Its timestamp.
	Time time.Time
}

// Read all log lines into memory.
func readFileAsLines(path string) ([]*logLine, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %s: %s", path, err)
	}

	defer func() {
		err := fh.Close()
		if err != nil {
			log.Printf("Close: %s: %s", path, err)
		}
	}()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %s: %s", path, err)
		}
		defer func() {
			err := gz.Close()
			if err != nil {
				log.Printf("gzip Close: %s: %s", path, err)
			}
		}()

		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(fh)
	}

	// Increase default buffer size. I ran into max token errors in
	// apt/history.log.
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, cap(buf))

	lines := []*logLine{}

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || scanner.Text() == "(Nothing has been logged yet.)" {
			continue
		}

		lines = append(lines, &logLine{
			Log:  path,
			Line: text,
			// Don't figure out the time yet.
		})
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("scanner: %s", err)
	}

	return lines, nil
}

// assignTimeToLines sets a time stamp on each log line.
func assignTimeToLines(
	lines []*logLine,
	config LogConfig,
	location *time.Location,
	modTime time.Time,
) error {

	// Track the last time we were able to parse a line's time in this log.
	// Why? Because some logs don't have a timestamp on every line but we can
	// apply a prior line's time as useful to a later line.
	var lastLineTime time.Time
	var zeroTime time.Time

	for _, line := range lines {
		lineTime, err := parseLineTime(line.Line, location, config.TimeRegexp,
			config.TimeLayouts)
		if err != nil {
			// Be generous and accept it anyway. Apply the last line's timestamp, but
			// warn about this happening.
			if config.TimestampStrategy == EveryLine {
				log.Printf("Warning: line's time could not be determined: %#v: %s",
					line, err)
				line.Time = lastLineTime
				continue
			}

			if config.TimestampStrategy == LastLine {
				// We've not yet seen any timestamp. We want to apply the timestamp
				// from the last log line that had one.
				if lastLineTime == zeroTime {
					return fmt.Errorf("line's time could not be determined: %#v: %s",
						line, err)
				}
				line.Time = lastLineTime
				continue
			}

			if config.TimestampStrategy == LastLineOrStat {
				if lastLineTime == zeroTime {
					line.Time = modTime
					continue
				}
				line.Time = lastLineTime
				continue
			}

			return fmt.Errorf("unexpected timestamp strategy: %d",
				config.TimestampStrategy)
		}

		line.Time = lineTime
		lastLineTime = lineTime
	}

	return nil
}

// parseLineTime attempts to parse the timestamp from the log line.
func parseLineTime(
	line string,
	location *time.Location,
	timeRegexp *regexp.Regexp,
	timeLayouts []string,
) (time.Time, error) {
	t, err := parseTimestamp(line, location, timeRegexp, timeLayouts)
	if err != nil {
		return time.Time{}, err
	}

	// Unspecified fields become zero. Like year for time layouts. Put zero years
	// in the current year. Yes, this is invalid when we roll over in
	// December/January if we're not careful.
	if t.Year() == 0 {
		// Assumption: If it is January and the line we see is in December, then it
		// is in the current year - 1. Otherwise, put the line in the current year.
		year := time.Now().Year()
		if time.Now().Month() == time.January && t.Month() == time.December {
			year = time.Now().Year() - 1
		}

		t = t.AddDate(year, 0, 0)
	}

	return t, nil
}

func parseTimestamp(
	line string,
	location *time.Location,
	timeRegexp *regexp.Regexp,
	timeLayouts []string,
) (time.Time, error) {
	if timeRegexp != nil {
		matches := timeRegexp.FindStringSubmatch(line)
		if matches == nil {
			return time.Time{}, fmt.Errorf("time regexp did not match on line")
		}
		line = matches[1]
	}

	for _, layout := range timeLayouts {
		// ParseInLocation does not like there to be extra text. It wants only the
		// timestamp portion to be present. Let's try to strip off only the
		// timestamp.
		//
		// I do this by counting how many spaces are in the layout, and then trying
		// to copy from the line until we have the same number of spaces copied.
		var lastChar rune
		timestamp := ""
		for _, c := range line {
			if c == ' ' {
				// Stop when we have as many space blocks as the layout. Ensure we
				// don't mistake a new block for the current one by checking the last
				// character we saw.
				if countCharBlocksInString(timestamp, ' ') ==
					countCharBlocksInString(layout, ' ') &&
					lastChar != ' ' {
					break
				}
			}

			timestamp += string(c)
			lastChar = c
		}

		t, err := time.ParseInLocation(layout, timestamp, location)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse line's timestamp")
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

func filterLogLines(
	allIgnorePatterns []*regexp.Regexp,
	config LogConfig,
	lines []*logLine,
) []*logLine {
	var interestingLines []*logLine
	for _, line := range lines {
		keep := filterLine(config, allIgnorePatterns, line.Line)
		if !keep {
			continue
		}
		interestingLines = append(interestingLines, line)
	}
	return interestingLines
}

func filterLine(
	config LogConfig,
	allIgnorePatterns []*regexp.Regexp,
	line string,
) bool {
	var ignorePatterns []*regexp.Regexp
	if config.IncludeAllIgnorePatterns {
		ignorePatterns = allIgnorePatterns
	} else {
		ignorePatterns = config.IgnorePatterns
	}

	for _, re := range ignorePatterns {
		if re.MatchString(line) {
			return false
		}
	}

	return true
}

func ship(ctx context.Context, email, projectID, topic, report string) error {
	hostname, err := getHostname()
	if err != nil {
		return err
	}

	m := pubSubMessage{
		Body:    report,
		Subject: "Logs for " + hostname,
		To:      email,
	}

	buf, err := json.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "error generating JSON")
	}

	c, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		return errors.Wrap(err, "error creating pubsub client")
	}

	t := c.Topic(topic)

	res := t.Publish(
		ctx,
		&pubsub.Message{
			Data: buf,
		},
	)
	defer t.Stop()

	if _, err := res.Get(ctx); err != nil {
		return errors.Wrap(err, "error publishing")
	}

	return nil
}

// Retrieve system FQDN.
//
// NOTE: This is not portable.
func getHostname() (string, error) {
	cmd := exec.Command("hostname", "-f")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("unable to run hostname command: %s", err)
	}

	hostname := strings.TrimSpace(string(output))
	if len(hostname) == 0 {
		return "", fmt.Errorf("no hostname found")
	}

	return hostname, nil
}

type pubSubMessage struct {
	Body    string
	Subject string
	To      string
}
