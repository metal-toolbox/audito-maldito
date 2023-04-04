package processors

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
	// loginRE matches the sshd login log message, allowing us to
	// extract information about the login attempt. At a minimum, it
	// should support the characters that "adduser" on Debian-based
	// systems cares about. For example, here is what "adduser"
	// says when given an invalid user name string:
	//
	//	# adduser /foo/
	//	adduser: To avoid problems, the username should consist
	//	only of letters, digits, underscores, periods, at signs
	//	and dashes, and not start with a dash (as defined by IEEE
	//	Std 1003.1-2001). For compatibility with Samba machine
	//	accounts $ is also supported at the end of the username
	//
	// It should also support unicode characters.
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	loginRE = regexp.MustCompile(`Accepted publickey for (?P<Username>\S+) from (?P<Source>\S+) port (?P<Port>\d+) ssh[[:alnum:]]+: (?P<Alg>[\w -]+):(?P<SSHKeySum>\S+)`)

	// certIDRE matches the sshd user-certificate log message,
	// allowing us to extract information about the user's
	// SSH certificate.
	certIDRE = regexp.MustCompile(`ID (?P<UserID>\S+)\s+\(serial (?P<Serial>\d+)\)\s+(?P<CA>.+)`)

	// notInAllowUsersRE matches the sshd AllowUsers violation message,
	// allowing us to extract information about the login violation.
	//
	//nolint:lll // This is a long regex... pretty hard to cut it without making it less readable.
	notInAllowUsersRE = regexp.MustCompile(`User (?P<Username>\w+) from (?P<Source>\S+) not allowed because not listed in AllowUsers`)

	// invalidUserRE matches the sshd invalid user log message,
	// allowing us to extract information about the user.
	invalidUserRE = regexp.MustCompile(`Invalid user (?P<Username>\w+) from (?P<Source>\S+) port (?P<Port>\d+)`)

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

type ProcessEntryConfig struct {
	Ctx       context.Context //nolint
	Logins    chan<- common.RemoteUserLogin
	LogEntry  string
	NodeName  string
	MachineID string
	When      time.Time
	Pid       string
	EventW    *auditevent.EventWriter
}

func ProcessEntry(config *ProcessEntryConfig) error {
	var entryFunc func(*ProcessEntryConfig) error
	switch {
	case strings.HasPrefix(config.LogEntry, "Accepted publickey"):
		entryFunc = processAcceptPublicKeyEntry
	case strings.HasPrefix(config.LogEntry, "Certificate invalid"):
		entryFunc = processCertificateInvalidEntry
	case strings.HasSuffix(config.LogEntry, "not allowed because not listed in AllowUsers"):
		entryFunc = processNotInAllowUsersEntry
	case strings.HasPrefix(config.LogEntry, "Invalid user"):
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

func processAcceptPublicKeyEntry(config *ProcessEntryConfig) error {
	matches := loginRE.FindStringSubmatch(config.LogEntry)
	if matches == nil {
		logger.Infoln("got login entry with no matches for identifiers")
		return nil
	}

	pid, err := strconv.Atoi(config.Pid)
	if err != nil {
		logger.Errorf("failed to convert pid string to int ('%s') - %s",
			config.Pid, err)
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
			"pid":      config.Pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.NodeName,
		"machine-id": config.MachineID,
	})

	evt.LoggedAt = config.When

	if len(config.LogEntry) == len(matches[0]) {
		// TODO: This log message is incorrect... but I am not sure
		//  what this logic is trying to accomplish.
		logger.Infoln("a: got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := config.EventW.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			return fmt.Errorf("failed to write event: %w", err)
		}
		select {
		case <-config.Ctx.Done():
			return nil
		case config.Logins <- common.RemoteUserLogin{
			Source:     evt,
			PID:        pid,
			CredUserID: common.UnknownUser,
		}:
			return nil
		}
	}

	certIdentifierStringStart := len(matches[0]) + 1
	certIdentifierString := config.LogEntry[certIdentifierStringStart:]
	idMatches := certIDRE.FindStringSubmatch(certIdentifierString)
	// RemoteUserLogin with extra padding
	if idMatches == nil {
		logger.Infoln("b: got login entry with no matches for certificate identifiers")
		addEventInfoForUnknownUser(evt, matches[algIdx], matches[keyIdx])
		if err := config.EventW.Write(evt); err != nil {
			// NOTE(jaosorior): Not being able to write audit events
			// merits us panicking here.
			return fmt.Errorf("failed to write event: %w", err)
		}
		select {
		case <-config.Ctx.Done():
			return nil
		case config.Logins <- common.RemoteUserLogin{
			Source:     evt,
			PID:        pid,
			CredUserID: common.UnknownUser,
		}:
			return nil
		}
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

	var debugLogger *zap.SugaredLogger
	if logger.Level().Enabled(zap.DebugLevel) {
		debugLogger = logger.With("eventPID", config.Pid)
		debugLogger.Debugln("writing event to auditevent writer...")
	}

	if err := config.EventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us panicking here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	if debugLogger != nil {
		debugLogger.Debugln("writing event to remote user logins channel...")

		defer func() {
			debugLogger.Debugln("finished writing event to remote user logins channel")
		}()
	}

	// RemoteUserLogin with CA entry
	select {
	case <-config.Ctx.Done():
		return nil
	case config.Logins <- common.RemoteUserLogin{
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

func processCertificateInvalidEntry(config *ProcessEntryConfig) error {
	reason := getCertificateInvalidReason(config.LogEntry)

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
			"pid":      config.Pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.NodeName,
		"machine-id": config.MachineID,
	})

	evt.LoggedAt = config.When

	ed, ederr := extraDataForInvalidCert(reason)
	if ederr != nil {
		logger.Errorf("failed to create extra data for invalid cert login event - %s", ederr)
	} else {
		evt = evt.WithData(ed)
	}

	if err := config.EventW.Write(evt); err != nil {
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

func processNotInAllowUsersEntry(config *ProcessEntryConfig) error {
	matches := notInAllowUsersRE.FindStringSubmatch(config.LogEntry)
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
			"pid":      config.Pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.NodeName,
		"machine-id": config.MachineID,
	})

	evt.LoggedAt = config.When
	if err := config.EventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us error-ing here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func processInvalidUserEntry(config *ProcessEntryConfig) error {
	matches := invalidUserRE.FindStringSubmatch(config.LogEntry)
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
			"pid":      config.Pid,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.NodeName,
		"machine-id": config.MachineID,
	})

	evt.LoggedAt = config.When
	if err := config.EventW.Write(evt); err != nil {
		// NOTE(jaosorior): Not being able to write audit events
		// merits us error-ing here.
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}
