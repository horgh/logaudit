package lib

import "testing"

func TestFileMatch(t *testing.T) {
	tests := []struct {
		Root    string
		Path    string
		Pattern string
		Output  bool
	}{
		{
			"/var/log",
			"/var/log/lighttpd/example.com/test.log",
			"lighttpd/example.com/test.log",
			true,
		},
	}

	for _, test := range tests {
		match, err := FileMatch(test.Root, test.Path, test.Pattern)
		if err != nil {
			t.Errorf("FileMatch(%s, %s, %s) = error %s, wanted nil", test.Root,
				test.Path, test.Pattern, err)
			continue
		}

		if match != test.Output {
			t.Errorf("FileMatch(%s, %s, %s) = %t, wanted %t", test.Root,
				test.Path, test.Pattern, match, test.Output)
			continue
		}
	}
}
