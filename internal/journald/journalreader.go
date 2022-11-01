//go:build linux
// +build linux

package journald

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

type journalEntryImpl struct {
	entry *sdjournal.JournalEntry
}

type journalReaderImpl struct {
	journal *sdjournal.Journal
}

func newJournalReader(bootID string, distro util.DistroType) (JournalReader, error) {
	j, err := sdjournal.NewJournal()
	if err != nil {
		return nil, fmt.Errorf("failed to open journal: %w", err)
	}

	if j == nil {
		return nil, errors.New("journal is nil")
	}

	if bootID == "" {
		bootID, err = j.GetBootID()
		if err != nil {
			_ = j.Close()
			return nil, fmt.Errorf("failed to get boot id from journal: %w", err)
		}
	}

	// Initialize/restart the journal reader.
	j.FlushMatches()

	matchSSH, err := getDistroSpecificMatch(distro)
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("failed to get journal ssh match: %w", err)
	}

	if err := j.AddMatch(matchSSH.String()); err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("failed to add ssh match: %w", err)
	}

	logger.Infof("distro: '%s' | boot id: '%s'", distro, bootID)

	// NOTE(jaosorior): We only care about the current boot
	matchBootID := sdjournal.Match{
		Field: sdjournal.SD_JOURNAL_FIELD_BOOT_ID,
		Value: bootID,
	}

	if err := j.AddMatch(matchBootID.String()); err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("failed to add boot id match: %w", err)
	}

	// Attempt to get the last read position from the journal.
	lastRead, reason := common.GetLastRead()
	if lastRead == 0 {
		logger.Infof("no last read position found, "+
			"reading from the beginning (reason: '%s')", reason)
	} else {
		logger.Infof("last read position: %d", lastRead)
		if err := j.SeekRealtimeUsec(lastRead + 1); err != nil {
			logger.Errorf("failed to seek to last read position, "+
				"attempting to continue anyway (err: '%s')", err)
		}
	}

	return &journalReaderImpl{
		journal: j,
	}, nil
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

func (je *journalEntryImpl) GetPID() string {
	pid, ok := je.entry.Fields[sdjournal.SD_JOURNAL_FIELD_PID]
	if !ok {
		return ""
	}

	return pid
}

func getDistroSpecificMatch(distro util.DistroType) (sdjournal.Match, error) {
	switch distro {
	case util.DistroFlatcar:
		return sdjournal.Match{
			Field: sdjournal.SD_JOURNAL_FIELD_SYSTEMD_SLICE,
			Value: "system-sshd.slice",
		}, nil
	case util.DistroUbuntu:
		return sdjournal.Match{
			Field: sdjournal.SD_JOURNAL_FIELD_SYSTEMD_UNIT,
			Value: "ssh.service",
		}, nil
	case util.DistroUnknown:
		return sdjournal.Match{}, errors.New("unknown os distro (literally)")
	default:
		return sdjournal.Match{}, fmt.Errorf("unsupported os distro: '%s'", distro)
	}
}
