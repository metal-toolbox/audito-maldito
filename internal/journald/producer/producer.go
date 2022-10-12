package producer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sync"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func initJournalReader(mid string, bootID string) *sdjournal.Journal {
	j, err := sdjournal.NewJournalFromFiles(filepath.Join("/var/log/journal", mid, "system.journal"))

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

	j.AddMatch(matchSSH.String())

	log.Printf("Boot-ID: %s\n", bootID)

	// NOTE(jaosorior): We only care about the current boot
	matchBootID := sdjournal.Match{
		Field: sdjournal.SD_JOURNAL_FIELD_BOOT_ID,
		Value: bootID,
	}

	j.AddMatch(matchBootID.String())

	// Attempt to get the last read position from the journal
	lastRead := common.GetLastRead()
	if lastRead != 0 {
		log.Printf("journaldConsumer: Last read position: %d", lastRead)
		j.SeekRealtimeUsec(lastRead + 1)
	} else {
		log.Printf("journaldConsumer: No last read position found, reading from the beginning")
	}

	return j
}

func JournaldProducer(ctx context.Context, wg *sync.WaitGroup, journaldChan chan<- *sdjournal.JournalEntry, bootID string) {
	defer wg.Done()

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		log.Fatal(fmt.Errorf("failed to get machine id: %w", miderr))
	}
	log.Printf("Machine-ID: %s\n", mid)

	j := initJournalReader(mid, bootID)
	defer j.Close()

	for {
		select {
		case <-ctx.Done():
			log.Println("journaldProducer: Interrupt received, exiting")
			// TODO(jaosorior): Store the last read position in the journal
			return
		default:
			c, nextErr := j.Next()
			if errors.Is(nextErr, io.EOF) {
				// TODO wait
				return
			} else if nextErr != nil {
				log.Fatal(fmt.Errorf("failed to read next journal entry: %w", nextErr))
			}

			if c == 0 {
				continue
			}

			entry, geErr := j.GetEntry()
			if geErr != nil {
				log.Println("journaldProducer: Error getting entry")
				continue
			}

			journaldChan <- entry
		}
	}
}
