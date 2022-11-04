package journald

import "time"

type JournalEntry interface {
	GetMessage() (string, bool)

	// GetTimeStamp returns the wallclock time in microseconds
	// (since epoch) that the entry occurred at.
	//
	// From the systemd documentation for "__REALTIME_TIMESTAMP":
	//
	//   "The wallclock time (CLOCK_REALTIME) at the point in time
	//   the entry was received by the journal, in microseconds
	//   since the epoch UTC, formatted as a decimal string."
	//
	// Refer to the following documentation for more information:
	// https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
	GetTimeStamp() uint64

	GetPID() string
}

type JournalReader interface {
	// Next advances the read pointer into the journal by one entry.
	//
	// According to systemd, the returned integer can be:
	//  - Negative number (error code, in which case the corresponding
	//    error object is non-nil)
	//  - 0 - If Next is still pointing to the same file
	//  - 1 - If Next is pointing to a new file
	//
	// Refer to the following source file for details:
	// https://github.com/systemd/systemd/blob/main/src/libsystemd/sd-journal/sd-journal.c#L815-L867
	Next() (uint64, error)

	// GetEntry returns a full representation of the journal entry
	// referenced by the last completed Next/Previous function call,
	// with all key-value pairs of data as well as address fields
	// (cursor, realtime timestamp and monotonic timestamp).
	//
	// To call GetEntry, you must first have called one of the
	// Next/Previous functions.
	GetEntry() (JournalEntry, error)

	// Wait will synchronously wait until the journal gets changed.
	// The maximum time this call sleeps may be controlled with the
	// timeout parameter.
	//
	// If sdjournal.IndefiniteWait is passed as the timeout parameter,
	// Wait will wait indefinitely for a journal change.
	Wait(time.Duration) int

	// Close closes a journal opened with NewJournal.
	Close() error
}
