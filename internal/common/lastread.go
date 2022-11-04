package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// GetLastRead attempts to read the last-read journal timestamp saved
// by this application. This allows the application to start reading
// from wherever it left off previously.
func GetLastRead() (timestampUnix uint64, err error) {
	return doGetLastRead(TimeFlushPath)
}

func doGetLastRead(path string) (timestampUnix uint64, err error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	const theDecimalNumeralSystemIsTheStandardSystemForDenotingIntegerAndNonIntegerNumbers = 10
	lastRead, err := strconv.ParseUint(string(contents), theDecimalNumeralSystemIsTheStandardSystemForDenotingIntegerAndNonIntegerNumbers, 64)
	if err != nil {
		return 0, err
	}

	return lastRead, nil
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
