package producer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/journald/types"
)

var defaultSleep = 10 * time.Millisecond

func JournaldProducer(ctx context.Context, wg *sync.WaitGroup, journaldChan chan<- *types.LogEntry, bootID string) {
	defer wg.Done()

	j := newJournalReader(bootID)
	defer j.Close()

	for {
		select {
		case <-ctx.Done():
			log.Printf("journaldProducer: Exiting because context is done: %v", ctx.Err())
			return
		default:
			c, nextErr := j.Next()
			if errors.Is(nextErr, io.EOF) {
				if r := j.Wait(defaultSleep); r < 0 {
					log.Printf("journaldProducer: journal wait returned an error, reinitializing. error-code: %d", r)
					j = newJournalReader(bootID)
					continue
				}
				return
			} else if nextErr != nil {
				log.Fatal(fmt.Errorf("failed to read next journal entry: %w", nextErr))
			}

			if c == 0 {
				if r := j.Wait(defaultSleep); r < 0 {
					log.Printf("journaldProducer: journal wait returned an error, reinitializing. error-code: %d", r)
					j = newJournalReader(bootID)
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
			}

			select {
			case journaldChan <- lg:
			case <-ctx.Done():
				log.Printf("journaldProducer: Exiting because context is done: %v", ctx.Err())
				return
			}
		}
	}
}
