//
// This program extracts log lines from a database. The database receives its
// log lines through the logauditsubmit program running on hosts sending their
// logs to a logauditd server.
//
// It applies patterns to hide irrelevant log messages.
//
// The intention is to be able to easily monitor logs on different hosts.
//
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"summercat.com/logaudit/lib"
)

// Args holds the command line arguments.
type Args struct {
	// Verbose output.
	Verbose bool

	// ConfigFile is the file describing the logs to look at.
	ConfigFile string

	// StateFile is a file we record our starting runtime in. We can look at this
	// file as a way to base when to filter logs starting from.
	StateFile string

	// ShowIgnoredOnly is a flag to do the inverse of usual operations. I figure
	// it may be useful to see what the program excludes for some double checking.
	ShowIgnoredOnly bool
}

// Config holds global run time configuration.
type Config struct {
	DBHost string
	DBPort int
	DBUser string
	DBPass string
	DBName string
}

// LogConfig is a block read from the config file. It describes what to do with
// a set of logs.
type LogConfig struct {
	// A glob style file pattern. It should be relative to the LogDir.
	// e.g., auth.log*
	FilenamePattern string

	// IncludeAllIgnorePatterns causes log patterns from every LogConfig to be
	// used when examining the matched log. This is because some logs have lines
	// from other logs (syslog for instance).
	IncludeAllIgnorePatterns bool

	// IgnorePatterns holds the regular expressions that we apply to determine
	// whether a log line should be ignored or not.
	IgnorePatterns []*regexp.Regexp
}

// ByTime is provides sorting LogLines by time.
type ByTime []*lib.LogLine

func (s ByTime) Less(i, j int) bool { return s[i].Time.Before(s[j].Time) }
func (s ByTime) Len() int           { return len(s) }
func (s ByTime) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func main() {
	log.SetFlags(0)

	runStartTime := time.Now()

	args, err := getArgs()
	if err != nil {
		log.Fatalf("Invalid argument: %s", err)
	}

	lastRunTime, err := lib.ReadStateFileTime(args.StateFile)
	if err != nil {
		log.Fatalf("Unable to read state file: %s", err)
	}
	log.Printf("Examining logs on or after %s.", lastRunTime)

	config, configs, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err)
	}

	err = auditLogs(config, configs, args.ShowIgnoredOnly, lastRunTime,
		args.Verbose)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err)
	}

	err = lib.WriteStateFile(args.StateFile, runStartTime)
	if err != nil {
		log.Fatalf("Problem writing state file: %s: %s", args.StateFile, err)
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	verbose := flag.Bool("verbose", false, "Enable verbose output.")
	config := flag.String("config", "", "Path to the configuration file.")
	stateFile := flag.String("state-file", "", "Path to the state file. Run start time gets recorded here. We filter log lines to those after the run time if the file is present when we start.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines.")

	flag.Parse()

	if len(*config) == 0 {
		flag.PrintDefaults()
		return Args{}, fmt.Errorf("You must provide a config file.")
	}
	fi, err := os.Stat(*config)
	if err != nil {
		return Args{}, fmt.Errorf("Invalid config file: %s", err)
	}
	if !fi.Mode().IsRegular() {
		return Args{}, fmt.Errorf("Invalid config file: %s: Not a regular file.",
			*config)
	}

	if len(*stateFile) == 0 {
		return Args{}, fmt.Errorf("You must provide a state file.")
	}

	return Args{
		Verbose:         *verbose,
		ConfigFile:      *config,
		StateFile:       *stateFile,
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
// IncludeAllIgnorePatterns: y or n
//   This causes all other log patterns to be included when ignoring lines in
//   the log. This is useful for logs that have lines that are also in other
//   lines, such as /var/log/syslog.
//
// Ignore: regexp
//   A regexp applied to each line. If it matches, the line gets ignored.
//
// There are also global (not related to a log file) settings:
//   DBHost
//   DBPort
//   DBUser
//   DBPass
//   DBName
//
// We ignore blank lines and # comments.
func parseConfig(configFile string) (*Config, []LogConfig, error) {
	fh, err := os.Open(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Open: %s: %s", configFile, err)
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	var config Config
	var configs []LogConfig
	var logConfig LogConfig

	// Track if we see the same ignore pattern multiple times.
	ignoreToFile := map[string]string{}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || strings.HasPrefix(text, "#") {
			continue
		}

		dbRe := regexp.MustCompile("^db-(\\S+): (.+)")
		matches := dbRe.FindStringSubmatch(text)
		if matches != nil {
			if matches[1] == "host" {
				config.DBHost = matches[2]
				continue
			}
			if matches[1] == "port" {
				port, err := strconv.Atoi(matches[2])
				if err != nil {
					return nil, nil, fmt.Errorf("Invalid port: %s: %s", matches[2], err)
				}
				config.DBPort = port
				continue
			}
			if matches[1] == "user" {
				config.DBUser = matches[2]
				continue
			}
			if matches[1] == "pass" {
				config.DBPass = matches[2]
				continue
			}
			if matches[1] == "name" {
				config.DBName = matches[2]
				continue
			}

			return nil, nil, fmt.Errorf("Invalid option: %s", text)
		}

		nameRe := regexp.MustCompile("^FilenamePattern: (.+)")
		matches = nameRe.FindStringSubmatch(text)
		if matches != nil {
			if logConfig.FilenamePattern != "" {
				configs = append(configs, logConfig)
			}
			logConfig = LogConfig{
				FilenamePattern: matches[1],
				IgnorePatterns:  []*regexp.Regexp{},
			}
			continue
		}

		includeAllRe := regexp.MustCompile("^IncludeAllIgnorePatterns: (y|n)$")
		matches = includeAllRe.FindStringSubmatch(text)
		if matches != nil {
			if logConfig.FilenamePattern == "" {
				return nil, nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}
			logConfig.IncludeAllIgnorePatterns = matches[1] == "y"
			continue
		}

		patternRe := regexp.MustCompile("^Ignore: (.+)")
		matches = patternRe.FindStringSubmatch(text)
		if matches != nil {
			if logConfig.FilenamePattern == "" {
				return nil, nil, fmt.Errorf("You must set FilenamePattern to start a config block.")
			}

			file, ok := ignoreToFile[matches[1]]
			if ok {
				log.Printf("Warning: Ignore pattern %s in file %s and %s (line %d)",
					matches[1], file, logConfig.FilenamePattern, lineNum)
			} else {
				ignoreToFile[matches[1]] = logConfig.FilenamePattern
			}

			logConfig.IgnorePatterns = append(logConfig.IgnorePatterns,
				regexp.MustCompile(matches[1]))
			continue
		}

		return nil, nil, fmt.Errorf("Unexpected line: %s", text)
	}

	// Ensure we store the last config block we were reading.
	if logConfig.FilenamePattern != "" {
		configs = append(configs, logConfig)
	}

	err = scanner.Err()
	if err != nil {
		return nil, nil, fmt.Errorf("Scanner: %s", err)
	}

	return &config, configs, nil
}

// auditLogs retrieves all logs on or after the given last run time.
//
// It matches up the log file for each line, and then applies filters based on
// what log it is.
func auditLogs(config *Config, configs []LogConfig, showIgnoredOnly bool,
	filterStartTime time.Time, verbose bool) error {

	// Gather all ignore patterns in one slice - we use them all at once sometimes
	// and this is handy.
	var ignorePatterns []*regexp.Regexp
	for _, logConfig := range configs {
		ignorePatterns = append(ignorePatterns, logConfig.IgnorePatterns...)
	}

	// Fetch log lines from the database.
	lines, err := fetchLines(config, filterStartTime)
	if err != nil {
		return fmt.Errorf("Unable to fetch lines from database: %s", err)
	}

	// Gather log lines together.
	// Key by the log pattern so we group related lines of logs together when we
	// output.
	logToLines := make(map[string][]*lib.LogLine)

	for _, line := range lines {
		config, match, err := getConfigForLogFile(lib.LogDir, line.Log, configs)
		if err != nil {
			return fmt.Errorf("Unable to look up log config: %s", err)
		}
		if !match {
			log.Printf("No config found for log: %s", line.Log)
			continue
		}

		keep := filterLine(config, ignorePatterns, line.Line, showIgnoredOnly,
			verbose)
		if !keep {
			continue
		}

		_, exists := logToLines[config.FilenamePattern]
		if !exists {
			logToLines[config.FilenamePattern] = []*lib.LogLine{}
		}

		logToLines[config.FilenamePattern] = append(
			logToLines[config.FilenamePattern], line)
	}

	// Sort keys (log patterns) first.
	logKeys := []string{}
	for k := range logToLines {
		logKeys = append(logKeys, k)
	}
	sort.Strings(logKeys)

	// Show each log's lines.
	for _, logKey := range logKeys {
		// Sort lines by time. This is because we've gathered them from logs in
		// order of their file names which is not representative of the actual
		// log entry time.
		sort.Sort(ByTime(logToLines[logKey]))

		for _, line := range logToLines[logKey] {
			log.Printf("%s: %s: %s", line.Hostname, line.Log, line.Line)
		}
	}

	return nil
}

// fetchLines retrieves log lines from the database.
//
// We retrieve only lines on or after the filter start time.
func fetchLines(config *Config,
	filterStartTime time.Time) ([]*lib.LogLine, error) {

	db, err := lib.GetDB(config.DBHost, config.DBUser, config.DBPass,
		config.DBName, config.DBPort)
	if err != nil {
		return nil, fmt.Errorf("Unable to get database handle: %s", err)
	}

	query := `SELECT hostname, filename, line, time FROM log_line
	WHERE time >= $1`

	rows, err := db.Query(query, filterStartTime)
	if err != nil {
		return nil, fmt.Errorf("Unable to query: %s", err)
	}

	lines := []*lib.LogLine{}

	for rows.Next() {
		hostname := ""
		filename := ""
		line := ""
		time := time.Time{}

		err := rows.Scan(&hostname, &filename, &line, &time)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("Unable to scan row: %s", err)
		}

		lines = append(lines, &lib.LogLine{
			Hostname: hostname,
			Log:      filename,
			Line:     line,
			Time:     time,
		})
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("Problem selecting from database: %s", err)
	}

	return lines, nil
}

// Look at each log config. If it matches the log file, return it. We return the
// first one that matches.
func getConfigForLogFile(root, file string,
	configs []LogConfig) (LogConfig, bool, error) {

	for _, config := range configs {
		match, err := lib.FileMatch(root, file, config.FilenamePattern)
		if err != nil {
			return LogConfig{}, false, fmt.Errorf("fileMatch: %s: %s", file, err)
		}

		if match {
			return config, true, nil
		}
	}

	return LogConfig{}, false, nil
}

// filterLine decides whether a line should be shown or not by applying our
// filters.
func filterLine(config LogConfig, allIgnorePatterns []*regexp.Regexp,
	line string, showIgnoredOnly bool, verbose bool) bool {

	var ignorePatterns []*regexp.Regexp
	if config.IncludeAllIgnorePatterns {
		ignorePatterns = allIgnorePatterns
	} else {
		ignorePatterns = config.IgnorePatterns
	}

	for _, re := range ignorePatterns {
		if re.MatchString(line) {
			if showIgnoredOnly {
				return true
			}
			return false
		}
	}

	if showIgnoredOnly {
		return false
	}

	return true
}
