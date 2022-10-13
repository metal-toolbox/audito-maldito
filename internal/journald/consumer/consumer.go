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

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald/types"
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
	err := os.WriteFile(common.TimeFlushPath, []byte(fmt.Sprintf("%d", lastRead)), 0o600)
	if err != nil {
		log.Printf("journaldConsumer: failed to write flush file: %s", err)
	}
}

func JournaldConsumer(ctx context.Context, wg *sync.WaitGroup, journaldChan <-chan *types.LogEntry, w *auditevent.EventWriter) {
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
		case entry := <-journaldChan:
			// This is an message that identifies a login
			if strings.HasPrefix(entry.Message, "Accepted publickey") {
				processAcceptPublicKeyEntry(entry.Message, mid, nodename, w)
			} else if strings.HasPrefix(entry.Message, "Certificate invalid") {
				processCertificateInvalidEntry(entry.Message, mid, nodename, w)
			}

			// Even if there was no match, we have already "processed" this
			// log entry, so we should reflect it as such.
			atomic.StoreUint64(&currentRead, entry.Timestamp)
		}
	}
}

func addEventInfoForUnknownUser(evt *auditevent.AuditEvent, alg, keySum string) {
	evt.Subjects["userID"] = common.UnknownUser
	ed, ederr := extraDataWithoutCA(alg, keySum)
	if ederr != nil {
		log.Println("journaldConsumer: Failed to create extra data for login event")
	} else {
		evt = evt.WithData(ed)
	}
}

func processAcceptPublicKeyEntry(logentry, nodename, mid string, w *auditevent.EventWriter) {
	matches := loginRE.FindStringSubmatch(logentry)
	if matches == nil {
		log.Println("journaldConsumer: Got login entry with no matches for identifiers")
		return
	}

	usrIdx := loginRE.SubexpIndex(idxLoginUserName)
	sourceIdx := loginRE.SubexpIndex(idxLoginSource)
	portIdx := loginRE.SubexpIndex(idxLoginPort)
	algIdx := loginRE.SubexpIndex(idxLoginAlg)
	keyIdx := loginRE.SubexpIndex(idxSSHKeySum)

	// TODO(jaosorior): Overwrite timestamp with the one from the log entry
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
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

	if len(logentry) == len(matches[0]) {
		log.Println("journaldConsumer: Got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		w.Write(evt)
		return
	}

	certIdentifierStringStart := len(matches[0]) + 1
	certIdentifierString := logentry[certIdentifierStringStart:]
	idMatches := certIDRE.FindStringSubmatch(certIdentifierString)
	if idMatches == nil {
		log.Println("journaldConsumer: Got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		w.Write(evt)
		return
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
}

func getCertificateInvalidReason(logentry string) string {
	prefix := "Certificate invalid: "
	prefixLen := len(prefix)

	if len(logentry) <= prefixLen {
		return "unknown reason"
	}

	return logentry[prefixLen:]
}

func processCertificateInvalidEntry(logentry, nodename, mid string, w *auditevent.EventWriter) {
	reason := getCertificateInvalidReason(logentry)

	// TODO(jaosorior): Overwrite timestamp with the one from the log entry
	// TODO(jaosorior): Figure out smart way of getting the source
	//                  For flatcar, we could get it from the CGROUP.... not sure for Ubuntu though
	// e.g.
	//   _SYSTEMD_CGROUP=/system.slice/system-sshd.slice/sshd@56-1.0.7.5:22-7.8.36.9:50101.service
	//   _SYSTEMD_UNIT=sshd@56-1.0.7.5:22-7.8.36.9:50101.service
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: "unknown",
			Extra: map[string]any{
				"port": "unknown",
			},
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": common.UnknownUser,
			"userID":   common.UnknownUser,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       nodename,
		"machine-id": mid,
	})

	ed, ederr := extraDataForInvalidCert(reason)
	if ederr != nil {
		log.Println("journaldConsumer: Failed to create extra data for invalid cert login event")
	} else {
		evt = evt.WithData(ed)
	}

	w.Write(evt)
}

func extraDataForInvalidCert(reason string) (*json.RawMessage, error) {
	extraData := map[string]string{
		"reason": reason,
	}
	raw, err := json.Marshal(extraData)
	rawmsg := json.RawMessage(raw)
	return &rawmsg, err
}
