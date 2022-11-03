// Package journald contains the functions for
// audito maldito to interact with journald
package journald

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
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
	currentTS uint64
	jr        JournalReader
}

func (jp *Processor) getJournalReader() JournalReader {
	return jp.jr
}

// ProcessJournal reads the journal and sends the events to the EventWriter.
func (jp *Processor) Read(ctx context.Context) error {
	// TODO: Do we need to store this value on a per-service basis?
	//  I don't think so... but we should answer that question :)
	lastRead, err := common.GetLastRead()
	if err != nil {
		logger.Infof("no last read timestamp found for journal - "+
			"reading from the beginning (reason: '%s')", err.Error())
		jp.currentTS = 0
	} else {
		logger.Infof("last read timestamp for journal is: '%d'", lastRead)
		jp.currentTS = lastRead
	}

	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, lastRead)
	if err != nil {
		return err
	}
	defer func() {
		jr := jp.getJournalReader()
		if jr != nil {
			jr.Close()
		}
	}()

	defer func() {
		// Using an anonymous function here allows us to save the
		// current value of currentTS. Using "defer(flushLastRead(...))"
		// results in the deferred function receiving an out-of-date
		// copy of the value.
		//
		// This can be simplified by making flushLastRead a method
		// on Processor... but the tradeoff between exposing all the
		// struct's fields to such a simple function is making me
		// second guess that.
		flushLastRead(jp.currentTS)
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("exiting because context is done: %v", ctx.Err())
			return nil
		default:
			if err := jp.readEntry(); err != nil {
				if errors.Is(err, ErrNonFatal) {
					continue
				}
				return err
			}
		}
	}
}

func (jp *Processor) readEntry() error {
	j := jp.getJournalReader()
	isNewFile, nextErr := j.Next()
	if nextErr != nil {
		if errors.Is(nextErr, io.EOF) {
			if r := j.Wait(defaultSleep); r < 0 {
				flushLastRead(jp.currentTS)

				logger.Infof("wait failed after calling next, reinitializing (error-code: %d)", r)
				time.Sleep(defaultSleep)

				if err := jp.resetJournal(); err != nil {
					return fmt.Errorf("failed to reset journal after next failed: %w", err)
				}
			}

			return nil
		}

		if closeErr := j.Close(); closeErr != nil {
			logger.Errorf("failed to close journal: %v", closeErr)
		}

		return fmt.Errorf("failed to read next journal entry: %w", nextErr)
	}

	if isNewFile == 0 {
		if r := j.Wait(defaultSleep); r < 0 {
			flushLastRead(jp.currentTS)

			logger.Errorf("wait failed after checking for new journal file, "+
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
		logger.Errorf("error getting entry: %v", geErr)
		return ErrNonFatal
	}

	entryMsg, hasMessage := entry.GetMessage()
	if !hasMessage {
		logger.Error("got entry with no message")
		return ErrNonFatal
	}

	// This comes from journald's RealtimeTimestamp field.
	usec := entry.GetTimeStamp()
	jp.currentTS = usec

	err := processEntry(&processEntryConfig{
		logEntry:  entryMsg,
		nodeName:  jp.NodeName,
		machineID: jp.MachineID,
		when:      time.UnixMicro(int64(usec)),
		pid:       entry.GetPID(),
		eventW:    jp.EventW,
	})
	if err != nil {
		return fmt.Errorf("failed to process journal entry '%s': %w", entryMsg, err)
	}

	return nil
}

func (jp *Processor) resetJournal() error {
	if err := jp.jr.Close(); err != nil {
		logger.Errorf("failed to close journal: %v", err)
	}

	var err error
	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, jp.currentTS)
	if err != nil {
		return fmt.Errorf("failed to reset journal: %w", err)
	}

	return nil
}
