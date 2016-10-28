//
// This program is intended to make creating Ignore patterns for logaudit easy.
//
// You provide it a log file, and it attempts to combine all similar log lines
// into one (dropping duplicates, etc). It also replaces pid numbers such as
// dhclient[1966] to dhclient\[\d+\].
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
	"strings"
)

// Args are command line arguments.
type Args struct {
	// LogFile is a path to a log file.
	LogFile string
}

func main() {
	log.SetFlags(0)

	args, err := getArgs()
	if err != nil {
		os.Exit(1)
	}

	lines, err := readFile(args.LogFile)
	if err != nil {
		log.Fatalf("Unable to read file: %s: %s", args.LogFile, err)
	}

	err = consolidateAndOutput(lines)
	if err != nil {
		log.Fatal(err)
	}
}

func getArgs() (*Args, error) {
	file := flag.String("file", "", "Path to a log file.")

	flag.Parse()

	if len(*file) == 0 {
		flag.PrintDefaults()
		return nil, fmt.Errorf("You must provide a file.")
	}

	return &Args{LogFile: *file}, nil
}

func readFile(file string) ([]string, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	lines := []string{}

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("Scanner: %s", err.Error())
	}

	return lines, nil
}

func consolidateAndOutput(lines []string) error {
	// Lines look like so (syslog):
	// Oct 23 06:31:46 snorri dhclient[1966]: DHCPACK of 192.168.1.3 from 192.168.1.25
	// Strip up to here ------^

	uniqueLines := map[string]struct{}{}

	for _, line := range lines {
		line = regexp.QuoteMeta(line)

		// Turn kernel: \[    0\.000000\] into kernel: \[\s*\d+\.\d+\]
		// I do this prior to split as note the space inside [] (sometimes).
		kernelRe := regexp.MustCompile("kernel: \\\\\\[\\s*\\d+\\\\\\.\\d+\\\\\\]")
		line = kernelRe.ReplaceAllString(line, "kernel: \\[\\s*\\d+\\.\\d+\\]")

		// Oct 10 15:15:15 and Oct  1 15:15:15 should split the same. Drop the
		// problematic extra space in the second.
		timeRe := regexp.MustCompile("^[A-Za-z]{3}\\s+\\d+")
		// We drop the date currently, so we can replace it with nonsense.
		line = timeRe.ReplaceAllString(line, "xxx 99")

		pieces := strings.Split(line, " ")

		// Turn dhclient[1234]: into dhclient[\d+]
		progName := pieces[4]
		pidRe := regexp.MustCompile("^([a-zA-Z0-9_.-]+)\\\\\\[\\d+\\\\\\]:$")
		matches := pidRe.FindStringSubmatch(progName)
		if matches != nil {
			progName = fmt.Sprintf("%s\\[\\d+\\]:", matches[1])
			pieces[4] = progName
		}

		strippedLine := strings.Join(pieces[4:], " ")

		uniqueLines[strippedLine] = struct{}{}
	}

	sortedLines := []string{}
	for line := range uniqueLines {
		sortedLines = append(sortedLines, line)
	}

	sort.Strings(sortedLines)

	for _, line := range sortedLines {
		fmt.Printf("Ignore: %s\n", line)
	}

	return nil
}
