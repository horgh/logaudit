/*
 * This program is to make examining log files on an Ubuntu GNU/Linux server
 * simpler.
 *
 * My use case is I admin such a server and want to keep an eye on the logs.
 * There are many log messages I don't really care about. I don't need to see
 * everything.
 *
 * This program will examine all log files in /var/log. It will report any it
 * does not know about so they can be supported. It will look at each log file
 * it knows about and trim out all log messages that I do not care to see. It
 * will then show only the useful ones. It does this based by using regular
 * expressions.
 *
 * I hope this to make monitoring the logs more efficient for me.
 *
 * I am sure there are other solutions out there to do things like this. However
 * I really want fine grained control and to know very deeply about what logs
 * I watch and what messages I see or do not see. I think creating my own will
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

	// IgnorePatterns holds the regular expressions that we apply to determine
	// whether a log line should be ignored or not.
	IgnorePatterns []*regexp.Regexp
}

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
	err = auditLogs(args.LogDir, logFiles, config, args.ShowIgnoredOnly)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err.Error())
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	logDir := flag.String("log-dir", "/var/log", "Path to directory containing logs.")
	config := flag.String("config", "", "Path to the configuration file. See logs.conf.sample for an example.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines. Note this won't show lines from files that are configured as fully ignored.")

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

	return Args{
		LogDir:          *logDir,
		ConfigFile:      *config,
		ShowIgnoredOnly: *showIgnored,
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
		fh.Close()
		return nil, fmt.Errorf("Stat: %s: %s", root, err.Error())
	}

	if !fi.IsDir() {
		fh.Close()
		return nil, fmt.Errorf("Root is not a directory: %s", root)
	}

	files, err := fh.Readdirnames(0)
	if err != nil {
		fh.Close()
		return nil, fmt.Errorf("Readdirnames: %s: %s", root, err.Error())
	}

	fh.Close()

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
	logConfigs []LogConfig, showIgnoredOnly bool) error {

	// Gather all ignore patterns in one slice - we use them all at once sometimes
	// and this is handy.
	var ignorePatterns []*regexp.Regexp
	for _, logConfig := range logConfigs {
		ignorePatterns = append(ignorePatterns, logConfig.IgnorePatterns...)
	}

	for _, logFile := range logFiles {
		err := auditLog(logDirRoot, logFile, logConfigs, ignorePatterns,
			showIgnoredOnly)
		if err != nil {
			return fmt.Errorf("auditLog: %s", err.Error())
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
func auditLog(logDirRoot string, logFile string, logConfigs []LogConfig,
	allIgnorePatterns []*regexp.Regexp, showIgnoredOnly bool) error {
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

		err = filterLogLines(logFile, ignorePatterns, showIgnoredOnly)
		if err != nil {
			return fmt.Errorf("filterLogLines: %s: %s", logFile, err.Error())
		}

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
	showIgnoredOnly bool) error {
	fh, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Open: %s: %s", path, err.Error())
	}

	defer fh.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return fmt.Errorf("gzip.NewReader: %s: %s", path, err.Error())
		}
		defer gz.Close()

		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(fh)
	}

LineLoop:
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 ||
			scanner.Text() == "(Nothing has been logged yet.)" {
			continue
		}

		for _, re := range ignoreRegexps {
			if re.MatchString(text) {
				if showIgnoredOnly {
					log.Printf("%s: %s", path, text)
				}
				continue LineLoop
			}
		}

		if !showIgnoredOnly {
			log.Printf("%s: %s", path, text)
		}
	}

	err = scanner.Err()
	if err != nil {
		return fmt.Errorf("Scanner: %s", err.Error())
	}

	return nil
}
