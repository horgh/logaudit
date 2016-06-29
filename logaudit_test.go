package main

import (
	"testing"
)

func TestCountCharBlocksInString(t *testing.T) {
	var tests = []struct {
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
