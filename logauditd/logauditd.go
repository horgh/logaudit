//
// logauditd accepts and stores logs sent via HTTP.
//
// It expects logauditsubmit clients to send it HTTP requests containing log
// lines. It decodes them and stores them in a database.
//
package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"summercat.com/logaudit/lib"
)

// Args holds the command line arguments.
type Args struct {
	// ConfigFile gives us run time information.
	ConfigFile string

	// Serve with FCGI protocol (true) or HTTP (false).
	FCGI bool
}

// Config holds run time configuration.
type Config struct {
	ListenHost string
	ListenPort int

	DBHost string
	DBPort int
	DBUser string
	DBPass string
	DBName string
}

// HTTPHandler allows us to pass information to our request handlers.
type HTTPHandler struct {
	Config Config
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)

	args, err := getArgs()
	if err != nil {
		log.Fatalf("Invalid argument: %s", err)
	}

	config, err := parseConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("Unable to parse config: %s", err)
	}

	hostPort := fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort)

	handler := HTTPHandler{Config: config}

	if args.FCGI {
		listener, err := net.Listen("tcp", hostPort)
		if err != nil {
			log.Fatalf("Unable to listen: %s", err)
		}

		log.Printf("Starting to serve requests on %s (FastCGI)", hostPort)

		err = fcgi.Serve(listener, handler)
		if err != nil {
			log.Fatalf("Unable to serve: %s", err)
		}
	} else {
		s := &http.Server{
			Addr:    hostPort,
			Handler: handler,
		}

		log.Printf("Starting to serve requests on %s (HTTP)", hostPort)

		err := s.ListenAndServe()
		if err != nil {
			log.Fatalf("Unable to serve: %s", err)
		}
	}
}

// getArgs retrieves and validates command line arguments.
func getArgs() (Args, error) {
	config := flag.String("config", "", "Path to the configuration file.")
	fcgi := flag.Bool("fcgi", true, "Serve using FastCGI (true) or as a regular HTTP server.")

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

	return Args{
		ConfigFile: *config,
		FCGI:       *fcgi,
	}, nil
}

// parseConfig reads the config file into memory.
//
// We ignore blank lines and # comments.
func parseConfig(configFile string) (Config, error) {
	fh, err := os.Open(configFile)
	if err != nil {
		return Config{}, fmt.Errorf("Open: %s: %s", configFile, err)
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	var config Config

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || strings.HasPrefix(text, "#") {
			continue
		}

		re := regexp.MustCompile("^(\\S+): (.+)")
		matches := re.FindStringSubmatch(text)
		if matches == nil {
			return Config{}, fmt.Errorf("Invalid config line: %s", text)
		}

		key := matches[1]
		value := matches[2]

		if key == "listen-host" {
			config.ListenHost = value
			continue
		}

		if key == "listen-port" {
			port, err := strconv.Atoi(value)
			if err != nil {
				return Config{}, fmt.Errorf("Invalid port: %s: %s", text, err)
			}
			config.ListenPort = port
			continue
		}

		if key == "db-host" {
			config.DBHost = value
			continue
		}

		if key == "db-port" {
			port, err := strconv.Atoi(value)
			if err != nil {
				return Config{}, fmt.Errorf("Invalid port: %s: %s", text, err)
			}
			config.DBPort = port
			continue
		}

		if key == "db-user" {
			config.DBUser = value
			continue
		}

		if key == "db-pass" {
			config.DBPass = value
			continue
		}

		if key == "db-name" {
			config.DBName = value
			continue
		}
	}

	err = scanner.Err()
	if err != nil {
		return Config{}, fmt.Errorf("Scanner: %s", err)
	}

	if len(config.ListenHost) == 0 ||
		len(config.DBHost) == 0 ||
		len(config.DBUser) == 0 ||
		len(config.DBPass) == 0 ||
		len(config.DBName) == 0 ||
		config.DBPort == 0 ||
		config.ListenPort == 0 {
		return Config{}, fmt.Errorf("Missing configuration key")
	}

	return config, nil
}

// ServeHTTP handles an HTTP request.
func (h HTTPHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	log.Printf("Serving [%s] request from [%s] to path [%s] (%d bytes)",
		r.Method, r.RemoteAddr, r.URL.Path, r.ContentLength)

	if r.Method == "POST" && r.URL.Path == "/submit" {
		h.submitRequest(rw, r)
		return
	}

	log.Printf("Unknown request.")
	rw.WriteHeader(http.StatusNotFound)
	_, _ = rw.Write([]byte("<h1>404 Not found</h1>"))
}

// submitRequest handles a submit log request.
//
// We decode JSON from the body, check the expected data is present, and store
// the logs into the database.
func (h HTTPHandler) submitRequest(rw http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	submission := lib.Submission{}
	err := decoder.Decode(&submission)
	if err != nil {
		log.Printf("Malformed body: %s", err)
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte("<h1>Bad request</h1>"))
		return
	}

	if len(submission.Hostname) == 0 {
		log.Printf("Request is missing a hostname")
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte("<h1>Bad request</h1>"))
		return
	}

	db, err := lib.GetDB(h.Config.DBHost, h.Config.DBUser, h.Config.DBPass,
		h.Config.DBName, h.Config.DBPort)
	if err != nil {
		log.Printf("Unable to get database handle: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte("<h1>Internal server error</h1>"))
		return
	}

	// Filter duplicate lines.
	// NOTE: This means if the same line legitimately occurs multiple times in
	//   the same second (the granularity we generally have for logs) then we will
	//   only insert it once. This is probably not always what we want but it is a
	//   tradeoff.
	lines, err := filterLines(db, submission.Hostname, submission.Lines,
		submission.EarliestLogTime)
	if err != nil {
		log.Printf("Unable to filter lines: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte("<h1>Internal server error</h1>"))
		return
	}

	// Insert log lines.
	err = insertLines(db, submission.Hostname, lines)
	if err != nil {
		log.Printf("Unable to insert log lines: %s", err)
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte("<h1>Internal server error</h1>"))
		return
	}

	log.Printf("Inserted %d/%d log lines for %s", len(lines),
		len(submission.Lines), submission.Hostname)

	// We don't need to write status ok. Write will do it.
	_, _ = rw.Write([]byte("OK"))
}

// filterLines removes any lines that are already present in the database.
//
// We may have duplicate lines as the submission programs try to avoid missing
// any by pulling lines from a delta time before their last run started.
//
// To do this I pull all lines from the start time for this host into memory and
// then compare.
func filterLines(db *sql.DB, hostname string, lines []*lib.LogLine,
	earliestLogTime time.Time) ([]*lib.LogLine, error) {

	query := `SELECT filename, line, time FROM log_line
	WHERE hostname = $1 AND time >= $2`

	rows, err := db.Query(query, hostname, earliestLogTime)
	if err != nil {
		return nil, fmt.Errorf("Unable to query: %s", err)
	}

	// Make line info a key in the map for fast lookup to see if the line is
	// present.
	dbLines := map[string]struct{}{}

	for rows.Next() {
		filename := ""
		line := ""
		time := time.Time{}

		err := rows.Scan(&filename, &line, &time)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("Unable to scan row: %s", err)
		}

		key := fmt.Sprintf("%s:%s:%s", filename, line, time)
		dbLines[key] = struct{}{}
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("Problem selecting from database: %s", err)
	}

	newLines := []*lib.LogLine{}

	for _, line := range lines {
		key := fmt.Sprintf("%s:%s:%s", line.Log, line.Line, line.Time)
		_, exists := dbLines[key]
		if exists {
			continue
		}
		newLines = append(newLines, line)
	}

	return newLines, nil
}

// insertLines inserts log lines into the database.
//
// Use COPY FROM for fast inserts.
func insertLines(db *sql.DB, hostname string, lines []*lib.LogLine) error {
	// We must have a transaction for COPY FROM.
	txn, err := db.Begin()
	if err != nil {
		return fmt.Errorf("Unable to start transaction: %s", err)
	}

	stmt, err := txn.Prepare(pq.CopyIn("log_line", "hostname", "filename", "line",
		"time"))
	if err != nil {
		_ = txn.Rollback()
		return fmt.Errorf("Unable to prepare statement: %s", err)
	}

	for _, line := range lines {
		_, err := stmt.Exec(hostname, line.Log, []byte(line.Line), line.Time)
		if err != nil {
			_ = stmt.Close()
			_ = txn.Rollback()
			return fmt.Errorf("Unable to insert line: %s", err)
		}
	}

	// Flush
	_, err = stmt.Exec()
	if err != nil {
		_ = stmt.Close()
		_ = txn.Rollback()
		return fmt.Errorf("Unable flush data from COPY: %s", err)
	}

	err = stmt.Close()
	if err != nil {
		_ = txn.Rollback()
		return fmt.Errorf("Unable to close statement: %s", err)
	}

	err = txn.Commit()
	if err != nil {
		return fmt.Errorf("Unable to commit transaction: %s", err)
	}

	return nil
}
