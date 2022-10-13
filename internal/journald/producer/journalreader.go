//go:build linux
// +build linux

package producer

import (
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

type journalEntryImpl struct {
	entry *sdjournal.JournalEntry
}

type journalReaderImpl struct {
	journal *sdjournal.Journal
}

func newJournalReader(bootID string) JournalReader {
	j, err := sdjournal.NewJournal()

	if bootID == "" {
		var err error
		bootID, err = j.GetBootID()
		if err != nil {
			log.Fatal(fmt.Errorf("failed to get boot id: %w", err))
		}
	}

	if err != nil {
		log.Fatal(fmt.Errorf("failed to open journal: %w", err))
	}

	if j == nil {
		log.Fatal(fmt.Errorf("journal is nil"))
	}

	// Initialize/restart the journal reader.
	j.FlushMatches()

	// NOTE(jaosorior): This only works for Flatcar
	matchSSH := sdjournal.Match{
		Field: sdjournal.SD_JOURNAL_FIELD_SYSTEMD_SLICE,
		Value: "system-sshd.slice",
	}

	if err := j.AddMatch(matchSSH.String()); err != nil {
		log.Fatal(fmt.Errorf("failed to add match: %w", err))
	}

	log.Printf("Boot-ID: %s\n", bootID)

	// NOTE(jaosorior): We only care about the current boot
	matchBootID := sdjournal.Match{
		Field: sdjournal.SD_JOURNAL_FIELD_BOOT_ID,
		Value: bootID,
	}

	if err := j.AddMatch(matchBootID.String()); err != nil {
		log.Fatal(fmt.Errorf("failed to add match: %w", err))
	}

	// Attempt to get the last read position from the journal
	lastRead := common.GetLastRead()
	if lastRead != 0 {
		log.Printf("journaldConsumer: Last read position: %d", lastRead)
		if err := j.SeekRealtimeUsec(lastRead + 1); err != nil {
			log.Printf("failed to seek to last read position: %s. Attempting to continue anyway.", err)
		}
	} else {
		log.Printf("journaldConsumer: No last read position found, reading from the beginning")
	}

	return &journalReaderImpl{
		journal: j,
	}
}

func (jr *journalReaderImpl) Next() (uint64, error) {
	return jr.journal.Next()
}

func (jr *journalReaderImpl) GetEntry() (JournalEntry, error) {
	entry, err := jr.journal.GetEntry()
	if err != nil {
		return nil, err
	}

	return &journalEntryImpl{
		entry: entry,
	}, nil
}

func (jr *journalReaderImpl) Wait(d time.Duration) int {
	return jr.journal.Wait(d)
}

func (jr *journalReaderImpl) Close() error {
	return jr.journal.Close()
}

func (je *journalEntryImpl) GetTimeStamp() uint64 {
	return je.entry.RealtimeTimestamp
}

func (je *journalEntryImpl) GetMessage() (string, bool) {
	msg, ok := je.entry.Fields[sdjournal.SD_JOURNAL_FIELD_MESSAGE]
	return msg, ok
}
