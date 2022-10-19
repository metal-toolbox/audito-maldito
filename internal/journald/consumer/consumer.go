package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

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
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	loginRE  = regexp.MustCompile(`Accepted publickey for (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+: (?P<Alg>[\w -]+):(?P<SSHKeySum>\S+)`)
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	notInAllowUsersRE = regexp.MustCompile(`User (?P<Username>\w+) from (?P<Source>\S+) not allowed because not listed in AllowUsers`)
	invalidUserRE     = regexp.MustCompile(`Invalid user (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+)`)
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

func extraDataWithCA(alg, keySum, certSerial, caData string) (*json.RawMessage, error) {
	extraData := map[string]string{
		idxLoginAlg:   alg,
		idxSSHKeySum:  keySum,
		idxCertSerial: certSerial,
		idxCertCA:     caData,
	}
	raw, err := json.Marshal(extraData)
	rawmsg := json.RawMessage(raw)
	return &rawmsg, err
}

// JournaldConsumer is the main loop that consumes journald log entries.
func JournaldConsumer(
	ctx context.Context,
	wg *sync.WaitGroup,
	journaldChan <-chan *types.LogEntry,
	w *auditevent.EventWriter,
) {
	mid, miderr := common.GetMachineID()
	if miderr != nil {
		log.Fatal(fmt.Errorf("failed to get machine id: %w", miderr))
	}

	nodename, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		log.Fatal(fmt.Errorf("failed to get node name: %w", nodenameerr))
	}

	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			log.Println("journaldConsumer: Interrupt received, exiting")
			return
		case entry := <-journaldChan:
			// This comes from journald's RealtimeTimestamp field.
			usec := entry.Timestamp
			ts := time.UnixMicro(int64(usec))
			pid := entry.PID

			processEntry(entry.Message, nodename, mid, ts, pid, w)
		}
	}
}

func processEntry(
	entry string,
	nodename, mid string,
	ts time.Time,
	pid string,
	w *auditevent.EventWriter,
) {
	var entryFunc func(string, string, string, time.Time, string, *auditevent.EventWriter)
	switch {
	case strings.HasPrefix(entry, "Accepted publickey"):
		entryFunc = processAcceptPublicKeyEntry
	case strings.HasPrefix(entry, "Certificate invalid"):
		entryFunc = processCertificateInvalidEntry
	case strings.HasSuffix(entry, "not allowed because not listed in AllowUsers"):
		entryFunc = processNotInAllowUsersEntry
	case strings.HasPrefix(entry, "Invalid user"):
		entryFunc = processInvalidUserEntry
	}

	entryFunc(entry, nodename, mid, ts, pid, w)

	// TODO(jaosorior): Should we log the entry if it didn't match?
}

func addEventInfoForUnknownUser(evt *auditevent.AuditEvent, alg, keySum string) {
	evt.Subjects["userID"] = common.UnknownUser
	ed, ederr := extraDataWithoutCA(alg, keySum)
	if ederr != nil {
		log.Println("journaldConsumer: Failed to create extra data for login event")
	} else {
		evt.WithData(ed)
	}
}

func processAcceptPublicKeyEntry(
	logentry string,
	nodename string,
	mid string,
	when time.Time,
	pid string,
	w *auditevent.EventWriter,
) {
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
			"pid":      pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       nodename,
		"machine-id": mid,
	})

	evt.LoggedAt = when

	if len(logentry) == len(matches[0]) {
		log.Println("journaldConsumer: Got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := w.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
		}
		return
	}

	certIdentifierStringStart := len(matches[0]) + 1
	certIdentifierString := logentry[certIdentifierStringStart:]
	idMatches := certIDRE.FindStringSubmatch(certIdentifierString)
	if idMatches == nil {
		log.Println("journaldConsumer: Got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := w.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
		}
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

	if err := w.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
	}
}

func getCertificateInvalidReason(logentry string) string {
	prefix := "Certificate invalid: "
	prefixLen := len(prefix)

	if len(logentry) <= prefixLen {
		return "unknown reason"
	}

	return logentry[prefixLen:]
}

func processCertificateInvalidEntry(
	logentry string,
	nodename string,
	mid string,
	when time.Time,
	pid string,
	w *auditevent.EventWriter,
) {
	reason := getCertificateInvalidReason(logentry)

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
			"pid":      pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       nodename,
		"machine-id": mid,
	})

	evt.LoggedAt = when

	ed, ederr := extraDataForInvalidCert(reason)
	if ederr != nil {
		log.Println("journaldConsumer: Failed to create extra data for invalid cert login event")
	} else {
		evt = evt.WithData(ed)
	}

	if err := w.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
	}
}

func extraDataForInvalidCert(reason string) (*json.RawMessage, error) {
	extraData := map[string]string{
		"error":  "certificate invalid",
		"reason": reason,
	}
	raw, err := json.Marshal(extraData)
	rawmsg := json.RawMessage(raw)
	return &rawmsg, err
}

func processNotInAllowUsersEntry(
	logentry string,
	nodename string,
	mid string,
	when time.Time,
	pid string,
	w *auditevent.EventWriter,
) {
	matches := notInAllowUsersRE.FindStringSubmatch(logentry)
	if matches == nil {
		log.Println("journaldConsumer: Got login entry with no matches for not-in-allow-users")
		return
	}

	usrIdx := notInAllowUsersRE.SubexpIndex(idxLoginUserName)
	sourceIdx := notInAllowUsersRE.SubexpIndex(idxLoginSource)

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: matches[sourceIdx],
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": matches[usrIdx],
			"userID":   common.UnknownUser,
			"pid":      pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       nodename,
		"machine-id": mid,
	})

	evt.LoggedAt = when
	if err := w.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
	}
}

func processInvalidUserEntry(
	logentry string,
	nodename string,
	mid string,
	when time.Time,
	pid string,
	w *auditevent.EventWriter,
) {
	matches := invalidUserRE.FindStringSubmatch(logentry)
	if matches == nil {
		log.Println("journaldConsumer: Got login entry with no matches for invalid-user")
		return
	}

	usrIdx := invalidUserRE.SubexpIndex(idxLoginUserName)
	sourceIdx := invalidUserRE.SubexpIndex(idxLoginSource)
	portIdx := invalidUserRE.SubexpIndex(idxLoginPort)

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: matches[sourceIdx],
			Extra: map[string]any{
				"port": matches[portIdx],
			},
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": matches[usrIdx],
			"userID":   common.UnknownUser,
			"pid":      pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       nodename,
		"machine-id": mid,
	})

	evt.LoggedAt = when
	if err := w.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		log.Fatal(fmt.Errorf("journaldConsumer: Failed to write event: %w", err))
	}
}
