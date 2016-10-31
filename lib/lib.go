//
// Package lib holds functionality common to different logaudit programs.
//
package lib

import "time"

// LogLine holds information about a single log line.
type LogLine struct {
	// Path to its log.
	Log string

	// The line itself.
	Line string

	// Its timestamp.
	Time time.Time
}

// Submission holds the data we send to the submission server.
type Submission struct {
	Hostname string
	// The earliest time a log line will have. We filter out any before this time.
	EarliestLogTime time.Time
	Lines           []*LogLine
}
