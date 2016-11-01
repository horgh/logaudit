//
// Package lib holds functionality common to different logaudit programs.
//
package lib

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// LogLine holds information about a single log line.
type LogLine struct {
	// Host that had the line. This is not always populated.
	Hostname string

	// Path to its log.
	Log string

	// The line itself.
	Line string

	// Its timestamp.
	Time time.Time
}

// Submission holds the data we send to the submission (logauditd) server.
type Submission struct {
	// Hostname sending the logs.
	Hostname string
	// The earliest time a log line will have. We filter out any before this time.
	EarliestLogTime time.Time
	// The lines themselves.
	Lines []*LogLine
}

// LogDir is the directory we find logs in.
const LogDir = "/var/log"

// DB is the database connection.
// This is so we try to share a single connection for multiple requests.
// NOTE: According to the database/sql documentation, the DB type
//   is indeed safe for concurrent use by multiple goroutines.
var DB *sql.DB

// DBLock helps us avoid race conditions associated with the database. Such as
// connecting to it (assigning the global).
var DBLock sync.Mutex

// ReadStateFileTime reads a state file.
//
// The file should contain a single value, a unixtime. Parse it and return.
//
// If the file does not exist, return 24 hours ago. It is okay for it not to
// exist as this could be the first run.
func ReadStateFileTime(path string) (time.Time, error) {
	_, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return time.Time{}, fmt.Errorf("Unable to stat state file: %s", err)
		}

		return time.Now().Add(-24 * time.Hour), nil
	}

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

// WriteStateFile writes the given time to the state file.
//
// The state file has no content other than a unixtime.
func WriteStateFile(path string, startTime time.Time) error {
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

// ConnectToDB opens a new connection to the database.
func ConnectToDB(host, user, pass, name string, port int) (*sql.DB, error) {
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d connect_timeout=10",
		user, pass, name, host, port)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to database: %s", err)
	}

	return db, nil
}

// GetDB connects us to the database if necessary, and returns an active
// database connection.
//
// We use the global DB variable to try to ensure we use a single connection.
func GetDB(host, user, pass, name string, port int) (*sql.DB, error) {
	// If we have a db connection, ensure that it is still available so that we
	// reconnect if it is not.
	if DB != nil {
		err := DB.Ping()
		if err == nil {
			return DB, nil
		}

		log.Printf("Database ping failed: %s", err)

		// Reconnect.
		DBLock.Lock()
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
		DBLock.Unlock()
	}

	DBLock.Lock()
	defer DBLock.Unlock()

	if DB != nil {
		return DB
	}

	db, err := ConnectToDB(host, user, pass, name, port)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to the database: %s", err)
	}

	DB = db

	return DB, nil
}

// FileMatch takes a root directory, the actual path to the log file, and a
// path pattern that should be a subdirectory under the root. It decides if the
// root plus the subdirectory pattern match the log file.
//
// The pattern is a filepath.Match() pattern.
func FileMatch(root string, file string, path string) (bool, error) {
	pattern := fmt.Sprintf("%s%c%s", root, os.PathSeparator, path)
	match, err := filepath.Match(pattern, file)
	if err != nil {
		return false, fmt.Errorf("filepath.Match: %s: %s: %s", pattern, file, err)
	}
	return match, nil
}
