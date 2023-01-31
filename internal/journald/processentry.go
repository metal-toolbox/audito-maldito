package journald

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
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
	loginRE  = regexp.MustCompile(`Accepted publickey for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+: (?P<Alg>[\w -]+):(?P<SSHKeySum>\S+)`)
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	notInAllowUsersRE = regexp.MustCompile(`User (?P<Username>\w+) from (?P<Source>\S+) not allowed because not listed in AllowUsers`)
	invalidUserRE     = regexp.MustCompile(`Invalid user (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+)`)

	logger *zap.SugaredLogger
)

func SetLogger(l *zap.SugaredLogger) {
	logger = l
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

type processEntryConfig struct {
	ctx       context.Context //nolint
	logins    chan<- common.RemoteUserLogin
	logEntry  string
	nodeName  string
	machineID string
	when      time.Time
	pid       string
	eventW    *auditevent.EventWriter
}

func processEntry(config *processEntryConfig) error {
	var entryFunc func(*processEntryConfig) error
	switch {
	case strings.HasPrefix(config.logEntry, "Accepted publickey"):
		entryFunc = processAcceptPublicKeyEntry
	case strings.HasPrefix(config.logEntry, "Certificate invalid"):
		entryFunc = processCertificateInvalidEntry
	case strings.HasSuffix(config.logEntry, "not allowed because not listed in AllowUsers"):
		entryFunc = processNotInAllowUsersEntry
	case strings.HasPrefix(config.logEntry, "Invalid user"):
		entryFunc = processInvalidUserEntry
	}

	if entryFunc != nil {
		return entryFunc(config)
	}

	// TODO(jaosorior): Should we log the entry if it didn't match?
	return nil
}

func addEventInfoForUnknownUser(evt *auditevent.AuditEvent, alg, keySum string) {
	evt.Subjects["userID"] = common.UnknownUser
	ed, ederr := extraDataWithoutCA(alg, keySum)
	if ederr != nil {
		logger.Errorf("failed to create extra data for login event: %s", ederr)
	} else {
		evt.WithData(ed)
	}
}

func processAcceptPublicKeyEntry(config *processEntryConfig) error {
	matches := loginRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got login entry with no matches for identifiers")
		return nil
	}

	pid, err := strconv.Atoi(config.pid)
	if err != nil {
		logger.Errorf("failed to convert pid string to int ('%s') - %s",
			config.pid, err)
		return nil
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
			"pid":      config.pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when

	if len(config.logEntry) == len(matches[0]) {
		// TODO: This log message is incorrect... but I am not sure
		//  what this logic is trying to accomplish.
		logger.Infoln("a: got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := config.eventW.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			return fmt.Errorf("failed to write event: %w", err)
		}
		return nil
	}

	certIdentifierStringStart := len(matches[0]) + 1
	certIdentifierString := config.logEntry[certIdentifierStringStart:]
	idMatches := certIDRE.FindStringSubmatch(certIdentifierString)
	if idMatches == nil {
		logger.Infoln("b :got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := config.eventW.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			return fmt.Errorf("failed to write event: %w", err)
		}
		return nil
	}

	userIdx := certIDRE.SubexpIndex(idxCertUserID)
	serialIdx := certIDRE.SubexpIndex(idxCertSerial)
	caIdx := certIDRE.SubexpIndex(idxCertCA)

	usernameFromCert := idMatches[userIdx]
	evt.Subjects["userID"] = usernameFromCert

	ed, ederr := extraDataWithCA(matches[algIdx], matches[keyIdx], idMatches[serialIdx], idMatches[caIdx])
	if ederr != nil {
		logger.Errorf("failed to create extra data for login event - %s", ederr)
	} else {
		evt = evt.WithData(ed)
	}

	if err := config.eventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	select {
	case <-config.ctx.Done():
		return nil
	case config.logins <- common.RemoteUserLogin{
		Source:     evt,
		PID:        pid,
		CredUserID: usernameFromCert,
	}:
		return nil
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

func processCertificateInvalidEntry(config *processEntryConfig) error {
	reason := getCertificateInvalidReason(config.logEntry)

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
			"pid":      config.pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when

	ed, ederr := extraDataForInvalidCert(reason)
	if ederr != nil {
		logger.Errorf("failed to create extra data for invalid cert login event - %s", ederr)
	} else {
		evt = evt.WithData(ed)
	}

	if err := config.eventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us error-ing here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
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

func processNotInAllowUsersEntry(config *processEntryConfig) error {
	matches := notInAllowUsersRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got login entry with no matches for not-in-allow-users")
		return nil
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
			"pid":      config.pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when
	if err := config.eventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us error-ing here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func processInvalidUserEntry(config *processEntryConfig) error {
	matches := invalidUserRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got login entry with no matches for invalid-user")
		return nil
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
			"pid":      config.pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when
	if err := config.eventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us error-ing here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}
