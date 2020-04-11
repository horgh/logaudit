package main

import (
	"regexp"
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		TimeRegexp  *regexp.Regexp
		TimeLayouts []string
		Line        string
		Output      time.Time
	}{
		{
			regexp.MustCompile(`^\S+ \S+ \S+ (\[\S+ \S+\])`),
			[]string{"[02/Jan/2006:15:04:05 -0700]"},
			`127.0.0.1 www.example.com - [29/Jul/2017:13:45:56 +0000] "GET /test"`,
			func() time.Time {
				tt, err := time.ParseInLocation(time.RFC3339, "2017-07-29T13:45:56Z",
					time.UTC)
				if err != nil {
					panic("unable to parse time: " + err.Error())
				}
				return tt
			}(),
		},
	}

	for _, test := range tests {
		ti, err := parseTimestamp(test.Line, time.UTC, test.TimeRegexp,
			test.TimeLayouts)
		if err != nil {
			t.Errorf("parseTimestamp(%s, %s, %s, %v) = error %s, wanted nil",
				test.Line, time.UTC, test.TimeRegexp, test.TimeLayouts, err)
			continue
		}

		if !test.Output.Equal(ti) {
			t.Errorf("parseTimestamp(%s, %s, %s, %v) = %s, wanted %s",
				test.Line, time.UTC, test.TimeRegexp, test.TimeLayouts, ti, test.Output)
			continue
		}
	}
}

func TestCountCharBlocksInString(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"abc", 0},
		{"a bc", 1},
		{"a  bc", 1},
	}

	for _, test := range tests {
		c := countCharBlocksInString(test.input, ' ')
		if c != test.want {
			t.Errorf("countCharBlocksInString(%q) = %v, want %v", test.input, c,
				test.want)
		}
	}
}
