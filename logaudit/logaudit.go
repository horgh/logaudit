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
	"database/sql"
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

	"github.com/horgh/logaudit/lib"
)

// Args holds the command line arguments.
type Args struct {
	// Verbose output.
	Verbose bool

	// ConfigFile is the file describing the logs to look at.
	ConfigFile string

	// ShowIgnoredOnly is a flag to do the inverse of usual operations. I figure
	// it may be useful to see what the program excludes for some double checking.
	ShowIgnoredOnly bool
}

// Config holds run time configuration, except for log file settings.
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

// Host holds information about a host that reports logs.
type Host struct {
	Hostname string
	// AuditedUntil records the last log we saw and audited from this host. It
	// means we've audited its logs up until this time.
	AuditedUntil time.Time
}

// ByTime is provides sorting LogLines by time.
type ByTime []*lib.LogLine

func (s ByTime) Less(i, j int) bool { return s[i].Time.Before(s[j].Time) }
func (s ByTime) Len() int           { return len(s) }
func (s ByTime) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func main() {
	log.SetFlags(0)

	args, err := getArgs()
	if err != nil {
		log.Fatalf("Invalid argument: %s", err)
	}

	config, configs, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err)
	}

	err = auditLogs(config, configs, args.ShowIgnoredOnly, args.Verbose)
	if err != nil {
		log.Fatalf("Failure examining logs: %s", err)
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	verbose := flag.Bool("verbose", false, "Enable verbose output.")
	config := flag.String("config", "", "Path to the configuration file.")
	showIgnored := flag.Bool("show-ignored-only", false, "Show ignored lines only.")

	flag.Parse()

	if len(*config) == 0 {
		flag.PrintDefaults()
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

	return Args{
		Verbose:         *verbose,
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
		return nil, nil, fmt.Errorf("open: %s: %s", configFile, err)
	}

	defer func() {
		err := fh.Close()
		if err != nil {
			log.Printf("Close failed: %s: %s", configFile, err)
		}
	}()

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
					return nil, nil, fmt.Errorf("invalid port: %s: %s", matches[2], err)
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

			return nil, nil, fmt.Errorf("invalid option: %s", text)
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
				return nil, nil, fmt.Errorf("you must set FilenamePattern to start a config block")
			}
			logConfig.IncludeAllIgnorePatterns = matches[1] == "y"
			continue
		}

		patternRe := regexp.MustCompile("^Ignore: (.+)")
		matches = patternRe.FindStringSubmatch(text)
		if matches != nil {
			if logConfig.FilenamePattern == "" {
				return nil, nil, fmt.Errorf("you must set FilenamePattern to start a config block")
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

		return nil, nil, fmt.Errorf("unexpected line: %s", text)
	}

	// Ensure we store the last config block we were reading.
	if logConfig.FilenamePattern != "" {
		configs = append(configs, logConfig)
	}

	err = scanner.Err()
	if err != nil {
		return nil, nil, fmt.Errorf("scanner: %s", err)
	}

	return &config, configs, nil
}

// auditLogs retrieves all logs on or after the given last run time.
//
// It matches up the log file for each line, and then applies filters based on
// what log it is.
//
// It outputs lines that pass the filters.
//
// It records the time of the most recent log for each host.
func auditLogs(config *Config, configs []LogConfig, showIgnoredOnly,
	verbose bool) error {
	db, err := lib.GetDB(config.DBHost, config.DBUser, config.DBPass,
		config.DBName, config.DBPort)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %s", err)
	}

	defer func() {
		err := db.Close()
		if err != nil {
			log.Printf("error closing the database connection: %s", err)
		}
	}()

	// Find the hosts that have sent lines, and the time of the log we most
	// recently saw. I track per host as, for example, a host might miss its
	// submission window, and we want to pick up where we left off for that host.
	// This is as opposed to having a single time cut off each run which could
	// lead to us missing logs for host(s) that didn't submit for some reason
	// before our last audit run.

	fetchStartTime := time.Now()
	if verbose {
		log.Printf("Fetching hosts...")
	}

	hosts, err := dbGetHosts(db)
	if err != nil {
		return fmt.Errorf("unable to retrieve hosts: %s", err)
	}

	if verbose {
		log.Printf("Fetched %d hosts in %s", len(hosts),
			time.Now().Sub(fetchStartTime))
	}

	hostToLogToLines, hostToTime, err := fetchAndFilterLines(configs, db, hosts,
		showIgnoredOnly, verbose)
	if err != nil {
		return fmt.Errorf("unable to fetch/filter lines: %s", err)
	}

	outputLines(hostToLogToLines)

	err = recordHostLogTimes(db, hosts, hostToTime)
	if err != nil {
		return fmt.Errorf("unable to record log times for hosts: %s", err)
	}

	return nil
}

// Retrieve all hosts and the last time we saw a log line from it.
func dbGetHosts(db *sql.DB) ([]Host, error) {
	// A host exists if it ever sent us log lines. We discover hosts this way as
	// this allows us to avoid a registration phase where a host would have to get
	// into the host table somehow.

	query := `SELECT DISTINCT hostname FROM log_line`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("unable to query: %s", err)
	}

	hostnames := []string{}

	for rows.Next() {
		hostname := ""

		err := rows.Scan(&hostname)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("unable to scan row: %s", err)
		}

		hostnames = append(hostnames, hostname)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("problem selecting from database: %s", err)
	}

	// For each host we found, see up until what time we've audited it (if any).

	query = `SELECT hostname, audited_until FROM host`

	rows, err = db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("unable to query: %s", err)
	}

	hostToTime := map[string]time.Time{}

	for rows.Next() {
		hostname := ""
		t := time.Time{}

		err := rows.Scan(&hostname, &t)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("unable to scan row: %s", err)
		}

		hostToTime[hostname] = t
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("problem selecting from database: %s", err)
	}

	// Combine what we found into one list of Hosts.

	hosts := []Host{}

	for _, hostname := range hostnames {
		t, ok := hostToTime[hostname]
		if !ok {
			// Default to 48 hours back if we've never audited this host yet.
			t = time.Now().Add(-48 * time.Hour)
		}

		hosts = append(hosts, Host{
			Hostname:     hostname,
			AuditedUntil: t,
		})
	}

	return hosts, nil
}

// Retrieve and filter log lines for all hosts.
//
// We return the lines in a map of the form:
// map: host ->
//    map: log file -> []log line
//
// We also return the timestamp of the most recent log line we see for each
// host. This is in a map keyed by hostname. This needs to be inside this
// function as we want to know the newest line we see, filtered out or not.
func fetchAndFilterLines(configs []LogConfig, db *sql.DB, hosts []Host,
	showIgnoredOnly, verbose bool) (map[string]map[string][]*lib.LogLine,
	map[string]time.Time, error) {
	// Gather all ignore patterns in one slice. Certain log files apply all
	// patterns at once.
	var ignorePatterns []*regexp.Regexp
	for _, config := range configs {
		ignorePatterns = append(ignorePatterns, config.IgnorePatterns...)
	}

	// Fetch logs for each host.

	hostToLogToLines := make(map[string]map[string][]*lib.LogLine)
	hostToNewest := make(map[string]time.Time)

	for _, host := range hosts {
		// Fetch lines after the most recent time we saw last time we ran (for this
		// host). But give some buffer around last log line we saw.
		filterStartTime := host.AuditedUntil.Add(-time.Hour)

		fetchStartTime := time.Now()
		if verbose {
			log.Printf("Fetching logs for host %s (start: %s)...", host.Hostname,
				filterStartTime)
		}

		lines, err := dbFetchLines(db, host.Hostname, filterStartTime)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to fetch lines from database: %s",
				err)
		}

		if verbose {
			log.Printf("Fetched logs for host %s in %s", host.Hostname,
				time.Now().Sub(fetchStartTime))
		}

		// Track the most recent line time we see for this host.
		hostToNewest[host.Hostname] = time.Time{}

		// Look at each line. Determine if it's the newest time we've seen, and then
		// filter it for whether we will want to report it.

		for _, line := range lines {
			if line.Time.After(hostToNewest[host.Hostname]) {
				hostToNewest[host.Hostname] = line.Time
			}

			config, match, err := getConfigForLogFile(lib.LogDir, line.Log, configs)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to look up log config: %s", err)
			}

			if !match {
				log.Printf("no config found for log: %s", line.Log)
				continue
			}

			keep := filterLine(config, ignorePatterns, line.Line, showIgnoredOnly,
				verbose)
			if !keep {
				continue
			}

			// Store the line for later reporting.

			_, exists := hostToLogToLines[line.Hostname]
			if !exists {
				hostToLogToLines[line.Hostname] = make(map[string][]*lib.LogLine)
			}

			_, exists = hostToLogToLines[line.Hostname][config.FilenamePattern]
			if !exists {
				hostToLogToLines[line.Hostname][config.FilenamePattern] =
					[]*lib.LogLine{}
			}

			hostToLogToLines[line.Hostname][config.FilenamePattern] = append(
				hostToLogToLines[line.Hostname][config.FilenamePattern], line)
		}
	}

	return hostToLogToLines, hostToNewest, nil
}

// Retrieve log lines for the host from the database.
//
// We retrieve only lines on or after the filter start time.
func dbFetchLines(db *sql.DB, hostname string,
	filterStartTime time.Time) ([]*lib.LogLine, error) {
	query := `
	SELECT hostname, filename, line, time
	FROM log_line
	WHERE time >= $1 AND hostname = $2
	`

	rows, err := db.Query(query, filterStartTime, hostname)
	if err != nil {
		return nil, fmt.Errorf("unable to query for host's lines: %s: %s", hostname,
			err)
	}

	lines := []*lib.LogLine{}

	for rows.Next() {
		hostname := ""
		filename := ""
		line := ""

		t := time.Time{}

		err := rows.Scan(&hostname, &filename, &line, &t)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("unable to scan row: %s", err)
		}

		lines = append(lines, &lib.LogLine{
			Hostname: hostname,
			Log:      filename,
			Line:     line,
			Time:     t,
		})
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("problem selecting from database: %s", err)
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
			return LogConfig{}, false, fmt.Errorf("matching file: %s: %s", file, err)
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

// Output the lines we retrieved.
//
// We output each one host's lines before going on to the next host.
//
// Each host's lines we sort first by the log file, and then by log line's
// time in that file.
//
// We output one log file for a host before going on to the next host.
func outputLines(hostToLogToLines map[string]map[string][]*lib.LogLine) {
	// Sort hostnames.

	sortedHosts := []string{}
	for k := range hostToLogToLines {
		sortedHosts = append(sortedHosts, k)
	}
	sort.Strings(sortedHosts)

	// Output logs for each host.

	for _, host := range sortedHosts {
		// Sort log filenames (well, filename patterns).

		sortedLogs := []string{}
		for k := range hostToLogToLines[host] {
			sortedLogs = append(sortedLogs, k)
		}
		sort.Strings(sortedLogs)

		// Output each log's lines.

		for _, logPattern := range sortedLogs {
			// Sort lines by time. We've gathered the lines in order of their file
			// names which is not representative of the actual log entry time.
			sort.Sort(ByTime(hostToLogToLines[host][logPattern]))

			for _, line := range hostToLogToLines[host][logPattern] {
				log.Printf("%s: %s: %s", line.Hostname, line.Log, line.Line)
			}
		}
	}
}

// Record the newest time for a log line we saw from each host. Update this in
// the database only if we have a newer log line than we saw last time.
func recordHostLogTimes(db *sql.DB, hosts []Host,
	hostToTime map[string]time.Time) error {
	// We may see logs for hosts that we never saw before. These will have shown
	// up in our host list but not yet be in our host table.

	// It's possible we did not see any new lines this run for a host. Don't set
	// the time in the host table to one earlier than is already there.

	for _, host := range hosts {
		newestTime := hostToTime[host.Hostname]

		// If the newest time is the same or before the last time we recorded, then
		// there's nothing to do either. This should not happen, but check just in
		// case.
		if newestTime.Before(host.AuditedUntil) ||
			newestTime.Equal(host.AuditedUntil) {
			continue
		}

		// We need to record the host was audited up until this time. Take care
		// because there may not be a record in the host table for the host.

		// UPSERT.
		query := `
		INSERT INTO host (hostname, audited_until) VALUES($1, $2)
		ON CONFLICT (hostname)
		DO UPDATE SET audited_until = EXCLUDED.audited_until
		`

		_, err := db.Exec(query, host.Hostname, newestTime)
		if err != nil {
			return fmt.Errorf("unable to store host audited time: %s: %s",
				host.Hostname, err)
		}
	}

	return nil
}
