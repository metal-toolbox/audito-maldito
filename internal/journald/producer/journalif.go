package producer

import "time"

type JournalEntry interface {
	GetMessage() (string, bool)
	GetTimeStamp() uint64
}

type JournalReader interface {
	Next() (uint64, error)
	GetEntry() (JournalEntry, error)
	Wait(time.Duration) int
	Close() error
}
