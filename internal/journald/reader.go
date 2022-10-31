// Package journald contains the functions for
// audito maldito to interact with journald
package journald

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/util"
)

// ErrNonFatal is returned when the error is not fatal
// and processing may continue.
var ErrNonFatal = errors.New("non-fatal error")

type Processor struct {
	BootID    string
	MachineID string
	NodeName  string
	Distro    util.DistroType
	EventW    *auditevent.EventWriter
	jr        JournalReader
	l         *log.Logger
}

func (jp *Processor) getJournalReader() JournalReader {
	return jp.jr
}

func (jp *Processor) configureLogger() {
	jp.l = log.Default()
	jp.l.SetFlags(log.LstdFlags | log.Lmsgprefix)
	jp.l.SetPrefix("journald-processor: ")
}

// ProcessJournal reads the journal and sends the events to the EventWriter.
func (jp *Processor) Read(ctx context.Context) error {
	var currentRead uint64

	jp.configureLogger()

	var err error
	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, jp.l)
	if err != nil {
		return err
	}
	defer func() {
		jr := jp.getJournalReader()
		if jr != nil {
			jr.Close()
		}
	}()

	defer flushLastRead(jp.l, &currentRead)

	for {
		select {
		case <-ctx.Done():
			jp.l.Printf("Exiting because context is done: %v", ctx.Err())
			return nil
		default:
			if err := jp.readEntry(&currentRead); err != nil {
				if errors.Is(err, ErrNonFatal) {
					continue
				}
				return err
			}
		}
	}
}

func (jp *Processor) readEntry(currentRead *uint64) error {
	j := jp.getJournalReader()
	isNewFile, nextErr := j.Next()
	if nextErr != nil {
		if errors.Is(nextErr, io.EOF) {
			if r := j.Wait(defaultSleep); r < 0 {
				flushLastRead(jp.l, currentRead)
				jp.l.Printf("wait failed after calling next, reinitializing (error-code: %d)", r)
				time.Sleep(defaultSleep)

				if err := jp.resetJournal(); err != nil {
					return fmt.Errorf("failed to reset journal after next failed: %w", err)
				}
			}

			return nil
		}

		if closeErr := j.Close(); closeErr != nil {
			jp.l.Printf("failed to close journal: %v", closeErr)
		}

		return fmt.Errorf("failed to read next journal entry: %w", nextErr)
	}

	if isNewFile == 0 {
		if r := j.Wait(defaultSleep); r < 0 {
			flushLastRead(jp.l, currentRead)
			jp.l.Printf("wait failed after checking for new journal file, "+
				"reinitializing. error-code: %d", r)
			time.Sleep(defaultSleep)

			if err := jp.resetJournal(); err != nil {
				return fmt.Errorf("failed to reset journal after wait failed: %w", err)
			}
		}
		return nil
	}

	entry, geErr := j.GetEntry()
	if geErr != nil {
		jp.l.Printf("Error getting entry: %v", geErr)
		return ErrNonFatal
	}

	entryMsg, hasMessage := entry.GetMessage()
	if !hasMessage {
		jp.l.Println("Got entry with no MESSAGE")
		return ErrNonFatal
	}

	// This comes from journald's RealtimeTimestamp field.
	usec := entry.GetTimeStamp()
	ts := time.UnixMicro(int64(usec))

	err := processEntry(&processEntryConfig{
		logEntry:  entryMsg,
		nodeName:  jp.NodeName,
		machineID: jp.MachineID,
		when:      ts,
		pid:       entry.GetPID(),
		eventW:    jp.EventW,
		logger:    jp.l,
	})
	if err != nil {
		return fmt.Errorf("failed to process journal entry '%s': %w", entryMsg, err)
	}

	return nil
}

func (jp *Processor) resetJournal() error {
	if err := jp.jr.Close(); err != nil {
		jp.l.Printf("failed to close journal: %v", err)
	}

	var err error
	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, jp.l)
	if err != nil {
		return fmt.Errorf("failed to reset journal: %w", err)
	}
	return nil
}
