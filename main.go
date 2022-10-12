package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/metal-toolbox/auditevent"
)

const (
	ActionLoginIdentifier = "UserLogin"
)

const (
	idxLoginUserName = "Username"
	idxLoginSource   = "Source"
	idxLoginPort     = "Port"
	idxLoginAlg      = "Alg"
	idxSSHKeySum     = "SSHKeySum"
	idxCertUserID    = "UserID"
	idxCertSerial    = "Serial"
	idxCertCA        = "CA"
)

var (
	loginRE  = regexp.MustCompile(`Accepted publickey for (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+: (?P<Alg>[\w_ -]+):(?P<SSHKeySum>\S+)`)
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)
)

func getMachineID() (string, error) {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(machineID)), nil
}

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

	return j
}

func journaldProducer(ctx context.Context, wg *sync.WaitGroup, journaldChan chan<- *sdjournal.JournalEntry, bootID string) {
	defer wg.Done()

	mid, miderr := getMachineID()
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

func extraDataWithoutCA(alg, keySum string) (*json.RawMessage, error) {
	extraData := map[string]string{
		idxLoginAlg:  alg,
		idxSSHKeySum: keySum,
	}
	raw, err := json.Marshal(extraData)
	rawmsg := json.RawMessage(raw)
	return &rawmsg, err
}

func extraDataWithCA(alg, keySum, certSerial, CAData string) (*json.RawMessage, error) {
	extraData := map[string]string{
		idxLoginAlg:   alg,
		idxSSHKeySum:  keySum,
		idxCertSerial: certSerial,
		idxCertCA:     CAData,
	}
	raw, err := json.Marshal(extraData)
	rawmsg := json.RawMessage(raw)
	return &rawmsg, err
}

func journaldConsumer(ctx context.Context, wg *sync.WaitGroup, journaldChan <-chan *sdjournal.JournalEntry) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("journaldConsumer: Interrupt received, exiting")
			return
		case msg := <-journaldChan:
			entryMsg, hasMessage := msg.Fields[sdjournal.SD_JOURNAL_FIELD_MESSAGE]
			if !hasMessage {
				log.Println("journaldConsumer: Got entry with no MESSAGE")
				continue
			}

			// This is an message that identifies a login
			if strings.HasPrefix(entryMsg, "Accepted publickey") {
				matches := loginRE.FindStringSubmatch(entryMsg)
				if matches == nil {
					log.Println("journaldConsumer: Got login entry with no matches for identifiers")
					continue
				}

				usrIdx := loginRE.SubexpIndex(idxLoginUserName)
				sourceIdx := loginRE.SubexpIndex(idxLoginSource)
				portIdx := loginRE.SubexpIndex(idxLoginPort)
				algIdx := loginRE.SubexpIndex(idxLoginAlg)
				keyIdx := loginRE.SubexpIndex(idxSSHKeySum)

				evt := auditevent.NewAuditEvent(
					ActionLoginIdentifier,
					auditevent.EventSource{
						Type:  "IP",
						Value: matches[sourceIdx],
						Extra: map[string]any{
							"port": matches[portIdx],
						},
					},
					auditevent.OutcomeSucceeded,
					map[string]string{
						"loggedAs": matches[usrIdx],
					},
					"sshd",
				).WithTarget(map[string]string{
					// TODO(jaosorior): Get host
					"host": "my-host",
				})

				certIdentifierStringStart := len(matches[0]) + 1
				certIdentifierString := entryMsg[certIdentifierStringStart:]
				idMatches := certIDRE.FindStringSubmatch(certIdentifierString)
				if idMatches == nil {
					log.Println("journaldConsumer: Got login entry with no matches for certificate identifiers")
					evt.Subjects["userID"] = "unknown"
					ed, ederr := extraDataWithoutCA(matches[algIdx], matches[keyIdx])
					if ederr != nil {
						log.Println("journaldConsumer: Failed to create extra data for login event")
					} else {
						evt = evt.WithData(ed)
					}
					log.Printf("audit event %v", evt)
					continue
				}

				userIdx := certIDRE.SubexpIndex(idxCertUserID)
				serialIdx := certIDRE.SubexpIndex(idxCertSerial)
				caIdx := certIDRE.SubexpIndex(idxCertCA)

				evt.Subjects["userID"] = idMatches[userIdx]

				ed, ederr := extraDataWithCA(matches[algIdx], matches[keyIdx], idMatches[serialIdx], idMatches[caIdx])
				if ederr != nil {
					log.Println("journaldConsumer: Failed to create extra data for login event")
				} else {
					evt = evt.WithData(ed)
				}

				log.Printf("audit event %v", evt)
				log.Printf("cursor: %v", msg.Cursor)
			}
		}
	}
}

func main() {
	var bootID string

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flag.StringVar(&bootID, "boot-id", "", "Boot-ID to read from the journal")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	flag.Parse()

	var wg sync.WaitGroup

	journaldChan := make(chan *sdjournal.JournalEntry, 1000)
	log.Println("Starting workers")

	wg.Add(1)
	go journaldProducer(ctx, &wg, journaldChan, bootID)

	wg.Add(1)
	go journaldConsumer(ctx, &wg, journaldChan)
	wg.Wait()

	log.Println("All workers finished")
}
