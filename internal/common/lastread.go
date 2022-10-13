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

// GetLastRead reads the last read position so we can start the journal reading from here
// We ignore errors and just read from the beginning if needed.
func GetLastRead() uint64 {
	return doGetLastRead(TimeFlushPath)
}

// Makes GetLastRead testable.
func doGetLastRead(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	var lastRead uint64
	_, err = fmt.Fscanf(f, "%d", &lastRead)
	if err != nil {
		return 0
	}
	return lastRead
}

// EnsureFlushDirectory ensures that the directory where we store the last read position exists.
func EnsureFlushDirectory() error {
	_, err := os.Stat(filepath.Dir(TimeFlushPath))
	if os.IsNotExist(err) {
		err := os.MkdirAll(filepath.Dir(TimeFlushPath), 0o755)
		if err != nil {
			return fmt.Errorf("failed to create flush directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to access flush directory: %w", err)
	}

	return nil
}
