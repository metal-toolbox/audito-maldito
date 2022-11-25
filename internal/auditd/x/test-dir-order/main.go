package main

import (
	"flag"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	log.SetFlags(0)

	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalln("please specify a single directory path to examine")
	}

	entries, err := os.ReadDir(flag.Arg(0))
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("%v", sortLogNamesOldToNew(entries))
}

func sortLogNamesOldToNew(dirEntries []os.DirEntry) []string {
	var oldestToNew []string

	// Filter unwanted files and directories.
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.Contains(entry.Name(), "audit.log") {
			continue
		}

		oldestToNew = append(oldestToNew, entry.Name())
	}

	if len(oldestToNew) == 0 {
		return nil
	}

	// Sort slice such that "audit.log.2" comes before "audit.log.1".
	//
	// Example:
	//   $ ls /var/log/audit/
	//   audit.log  audit.log.1  audit.log.2  audit.log.3  audit.log.4
	//   $ test-app /var/log/audit/
	//   [audit.log.4 audit.log.3 audit.log.2 audit.log.1 audit.log]
	sort.Slice(oldestToNew, func(i, j int) bool {
		return oldestToNew[i] > oldestToNew[j]
	})

	return oldestToNew
}
