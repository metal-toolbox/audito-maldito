package common

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// TimeFlushPath is a file that contains the timestamp
	// of the last-read journal entry.
	//
	// Refer to the RealtimeTimestamp field in the
	// sdjournal.JournalEntry struct for details.
	TimeFlushPath = "/var/run/audito-maldito/flush_time"
)

const (
	flushDirPerms = 0o750
)

// GetLastRead attempts to read the last-read timestamp saved by this
// application. This allows the application to start reading from
// wherever it left off previously.
//
// A value of 0 is returned if the timestamp file cannot be read
// or parsed.
//
// The returned string is non-empty if an error occurred trying to
// read or parse the file. Such scenarios are considered non-fatal.
// The error string is provided for informational purposes.
func GetLastRead() (timestampUnix uint64, info string) {
	return doGetLastRead(TimeFlushPath)
}

func doGetLastRead(path string) (timestampUnix uint64, info string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err.Error()
	}
	defer f.Close()

	var lastRead uint64
	_, err = fmt.Fscanf(f, "%d", &lastRead)
	if err != nil {
		return 0, err.Error()
	}

	return lastRead, "file contains a value of zero"
}

// EnsureFlushDirectory ensures that the directory where we store the
// last-read timestamp file exists.
func EnsureFlushDirectory() error {
	_, err := os.Stat(filepath.Dir(TimeFlushPath))
	if os.IsNotExist(err) {
		err := os.MkdirAll(filepath.Dir(TimeFlushPath), flushDirPerms)
		if err != nil {
			return fmt.Errorf("failed to create flush directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to access flush directory: %w", err)
	}

	return nil
}
