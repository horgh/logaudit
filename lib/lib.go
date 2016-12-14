//
// Package lib holds functionality common to different logaudit programs.
//
package lib

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

// ConnectToDB opens a new connection to the database.
func ConnectToDB(host, user, pass, name string, port int) (*sql.DB, error) {
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d connect_timeout=10",
		user, pass, name, host, port)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %s", err)
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
		return DB, nil
	}

	db, err := ConnectToDB(host, user, pass, name, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %s", err)
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
