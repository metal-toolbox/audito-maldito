package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/metal-toolbox/audito-maldito/internal/common"

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

// writes the last read timestamp to a file
// Note we don't fail if we can't write the file nor read the directory
// as we intend to go through the defer statements and exit.
// If this fails, we will just start reading from the beginning of the journal
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
	err := os.WriteFile(common.TimeFlushPath, []byte(fmt.Sprintf("%d", lastRead)), 0600)
	if err != nil {
		log.Printf("journaldConsumer: failed to write flush file: %s", err)
	}
}

func JournaldConsumer(ctx context.Context, wg *sync.WaitGroup, journaldChan <-chan *sdjournal.JournalEntry, w *auditevent.EventWriter) {
	var currentRead uint64 = 0
	defer wg.Done()

	defer flushLastRead(&currentRead)

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		log.Fatal(fmt.Errorf("failed to get machine id: %w", miderr))
	}

	nodename, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		log.Fatal(fmt.Errorf("failed to get node name: %w", nodenameerr))
	}

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
					"host":       nodename,
					"machine-id": mid,
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

				w.Write(evt)
				atomic.StoreUint64(&currentRead, msg.RealtimeTimestamp)
			}
		}
	}
}
