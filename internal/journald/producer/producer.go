package producer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald/types"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

var defaultSleep = 1 * time.Second

const (
	onlyUserReadable = 0o600
)

func resetJournal(j JournalReader, bootID string, distro util.DistroType) (JournalReader, error) {
	if err := j.Close(); err != nil {
		log.Printf("journaldProducer: failed to close journal: %v", err)
	}

	return newJournalReader(bootID, distro) //nolint
}

// writes the last read timestamp to a file
// Note we don't fail if we can't write the file nor read the directory
// as we intend to go through the defer statements and exit.
// If this fails, we will just start reading from the beginning of the journal.
func flushLastRead(lastReadToFlush *uint64) {
	lastRead := atomic.LoadUint64(lastReadToFlush)

	log.Printf("journaldConsumer: Flushing last read timestamp %d", lastRead)

	if err := common.EnsureFlushDirectory(); err != nil {
		log.Printf("journaldConsumer: Failed to ensure flush directory: %v", err)
		return
	}

	// The WriteFile function ensures the file will only contain
	// *exactly* what we write to it by either creating a new file,
	// or by truncating an existing file.
	err := os.WriteFile(common.TimeFlushPath, []byte(fmt.Sprintf("%d", lastRead)), onlyUserReadable)
	if err != nil {
		log.Printf("journaldConsumer: failed to write flush file: %s", err)
	}
}

// Config configures the JournaldProducer function.
type Config struct {
	Entries chan<- *types.LogEntry
	BootID  string
	Distro  util.DistroType
	Exited  chan<- error
}

// JournaldProducer monitors systemd journal(s) using the specified Config.
func JournaldProducer(ctx context.Context, config Config) {
	config.Exited <- journaldProducer(ctx, config)
}

// journaldProducer makes a Go-routine-oriented function behave more like
// a standard Go function by providing return values. This helps avoid
// easy-to-make mistakes like writing to a channel - but not returning,
// or potentially writing to the channel before any deferred function
// calls are executed.
func journaldProducer(ctx context.Context, config Config) error {
	var currentRead uint64

	j, err := newJournalReader(config.BootID, config.Distro)
	if err != nil {
		return err
	}
	defer j.Close()

	defer flushLastRead(&currentRead)

	for {
		select {
		case <-ctx.Done():
			log.Printf("journaldProducer: Exiting because context is done: %v", ctx.Err())
			return nil
		default:
			isNewFile, nextErr := j.Next()
			if nextErr != nil {
				if errors.Is(nextErr, io.EOF) {
					if r := j.Wait(defaultSleep); r < 0 {
						flushLastRead(&currentRead)
						log.Printf("journaldProducer: wait failed after calling next, "+
							"reinitializing. error-code: %d", r)
						time.Sleep(defaultSleep)

						j, err = resetJournal(j, config.BootID, config.Distro)
						if err != nil {
							return fmt.Errorf("failed to reset journal after next failed: %s", err)
						}
					}
					continue
				}

				if closeErr := j.Close(); closeErr != nil {
					log.Printf("journaldProducer: failed to close journal: %v", closeErr)
				}

				return fmt.Errorf("failed to read next journal entry: %w", nextErr)
			}

			if isNewFile == 0 {
				if r := j.Wait(defaultSleep); r < 0 {
					flushLastRead(&currentRead)
					log.Printf("journaldProducer: wait failed after checking for new journal file, "+
						"reinitializing. error-code: %d", r)
					time.Sleep(defaultSleep)

					j, err = resetJournal(j, config.BootID, config.Distro)
					if err != nil {
						return fmt.Errorf("failed to reset journal after wait failed: %w", err)
					}
				}
				continue
			}

			entry, geErr := j.GetEntry()
			if geErr != nil {
				log.Printf("journaldProducer: Error getting entry: %v", geErr)
				continue
			}

			entryMsg, hasMessage := entry.GetMessage()
			if !hasMessage {
				log.Println("journaldConsumer: Got entry with no MESSAGE")
				continue
			}

			lg := &types.LogEntry{
				Timestamp: entry.GetTimeStamp(),
				Message:   entryMsg,
				PID:       entry.GetPID(),
			}

			select {
			case config.Entries <- lg:
				// TODO: Re-evaluate last-read file saving logic.
				//  Refer to PR 20 for details:
				//  https://github.com/metal-toolbox/audito-maldito/pull/20
				atomic.StoreUint64(&currentRead, lg.Timestamp)
			case <-ctx.Done():
				log.Printf("journaldProducer: Exiting because context is done: %v", ctx.Err())
				return nil
			}
		}
	}
}
