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
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/processors"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

// ErrNonFatal is returned when the error is not fatal
// and processing may continue.
var ErrNonFatal = errors.New("non-fatal error")
var logger *zap.SugaredLogger

func SetLogger(l *zap.SugaredLogger) {
	logger = l
}

type Processor struct {
	BootID    string
	MachineID string
	NodeName  string
	Distro    util.DistroType
	EventW    *auditevent.EventWriter
	Logins    chan<- common.RemoteUserLogin
	CurrentTS uint64 // Microseconds since unix epoch.
	Health    *common.Health
	jr        JournalReader
}

func (jp *Processor) getJournalReader() JournalReader {
	return jp.jr
}

// Read reads the journal and sends the events to the EventWriter.
func (jp *Processor) Read(ctx context.Context) error {
	var err error

	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, jp.CurrentTS)
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
		// current value of CurrentTS. Using "defer(flushLastRead(...))"
		// results in the deferred function receiving an out-of-date
		// copy of the value.
		//
		// This can be simplified by making flushLastRead a method
		// on Processor... but the tradeoff between exposing all the
		// struct's fields to such a simple function is making me
		// second guess that.
		flushLastRead(jp.CurrentTS)
	}()

	jp.Health.OnReady()

	for {
		select {
		case <-ctx.Done():
			logger.Infof("exiting because context is done: %v", ctx.Err())
			return nil
		default:
			if err := jp.readEntry(ctx); err != nil {
				if errors.Is(err, ErrNonFatal) {
					continue
				}
				return err
			}
		}
	}
}

func (jp *Processor) readEntry(ctx context.Context) error {
	j := jp.getJournalReader()
	isNewFile, nextErr := j.Next()
	if nextErr != nil {
		if errors.Is(nextErr, io.EOF) {
			if r := j.Wait(defaultSleep); r < 0 {
				flushLastRead(jp.CurrentTS)

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
			flushLastRead(jp.CurrentTS)

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

	usec := entry.GetTimeStamp()
	jp.CurrentTS = usec

	err := processors.ProcessEntry(&processors.ProcessEntryConfig{
		Ctx:       ctx,
		Logins:    jp.Logins,
		LogEntry:  entryMsg,
		NodeName:  jp.NodeName,
		MachineID: jp.MachineID,
		When:      time.UnixMicro(int64(usec)),
		Pid:       entry.GetPID(),
		EventW:    jp.EventW,
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
	jp.jr, err = newJournalReader(jp.BootID, jp.Distro, jp.CurrentTS)
	if err != nil {
		return fmt.Errorf("failed to reset journal: %w", err)
	}

	return nil
}
