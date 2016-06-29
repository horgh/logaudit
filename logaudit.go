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
 * will then show only the useful ones.
 *
 * I hope this to make monitoring the logs more efficient.
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

type Args struct {
	LogDir          string
	ConfigFile      string
	ShowIgnoredOnly bool
}

type LogConfig struct {
	FilenamePattern          string
	FullyIgnore              bool
	IncludeAllIgnorePatterns bool
	IgnorePatterns           []*regexp.Regexp
}

func main() {
	log.SetFlags(0)

	args, err := getArgs()
	if err != nil {
		log.Fatalf("Invalid argument: %s", err.Error())
	}

	config, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err.Error())
	}

	// Find all log files.
	logFiles, err := findLogFiles(args.LogDir)
	if err != nil {
		log.Fatalf("Unable to find log files: %s", err.Error())
	}

	log.Printf("%v", logFiles)

	// Examine each log file one by one and output any relevant entries.
	err = auditLogs(args.LogDir, logFiles, config, args.ShowIgnoredOnly)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err.Error())
	}

	log.Printf("Done.")
}

func getArgs() (Args, error) {
	logDir := flag.String("log-dir", "/var/log", "Path to directory containing logs.")
	config := flag.String("config", "", "Path to the configuration file.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines. Note this won't show lines from files that are set as fully ignored.")

	flag.Parse()

	if len(*logDir) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a log directory.")
	}

	if len(*config) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a config file.")
	}

	return Args{
		LogDir:          *logDir,
		ConfigFile:      *config,
		ShowIgnoredOnly: *showIgnored,
	}, nil
}

// parseConfig reads the config file into memory.
//
// The config looks like this:
// FilenamePattern: path/filepath pattern
//   e.g. /var/log/auth.log*
// FullyIgnore: y or n
//   To ignore the file completely
// IncludeAllIgnorePatterns: y or n
//   This causes all other log patterns to be included when ignoring lines in
//   the log. This is useful for logs that have lines that are also in other
//   lines, such as /var/log/syslog.
// Ignore: regexp
//   A regexp applied to each line. If it matches, the line gets ignored.
//
// Blank lines and # comments we ignore.
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

	log.Printf("Entering directory [%s]", root)

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
		log.Printf("%s...", logFile)

		err := auditLog(logDirRoot, logFile, logConfigs, ignorePatterns,
			showIgnoredOnly)
		if err != nil {
			return fmt.Errorf("auditLog: %s", err.Error())
		}
	}

	return nil
}

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

func fileMatch(logDirRoot string, logFile string, path string) (bool, error) {
	pattern := fmt.Sprintf("%s%c%s", logDirRoot, os.PathSeparator, path)
	match, err := filepath.Match(pattern, logFile)
	if err != nil {
		return false, fmt.Errorf("filepath.Match: %s: %s: %s", pattern, logFile,
			err.Error())
	}
	if match {
		return true, nil
	}
	return false, nil
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
