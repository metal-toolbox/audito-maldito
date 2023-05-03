package sshd

import (
	"fmt"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func revokedPublicKeyByFile(config *SshdProcessorer) error {
	matches := revokedPublicKeyByFileRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got revokedPublicKeyByFile log with no string sub-matches")
		return nil
	}

	var keyType string
	keyTypeIdx := revokedPublicKeyByFileRE.SubexpIndex(idxSSHKeyType)
	if keyTypeIdx > -1 {
		keyType = matches[keyTypeIdx]
	}

	var fingerprint string
	fingerprintIdx := revokedPublicKeyByFileRE.SubexpIndex(idxSSHKeyFP)
	if fingerprintIdx > -1 {
		fingerprint = matches[fingerprintIdx]
	}

	var filePath string
	filePathIdx := revokedPublicKeyByFileRE.SubexpIndex(idxFilePath)
	if filePathIdx > -1 {
		filePath = matches[filePathIdx]
	}

	evt := revokedLogToAuditEvent(keyType, fingerprint, filePath, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func revokedPublicKeyByFileErr(config *SshdProcessorer) error {
	matches := revokedPublicKeyByFileErrRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got revokedPublicKeyByFileErr log with no string sub-matches")
		return nil
	}

	var keyType string
	keyTypeIdx := revokedPublicKeyByFileErrRE.SubexpIndex(idxSSHKeyType)
	if keyTypeIdx > -1 {
		keyType = matches[keyTypeIdx]
	}

	var fingerprint string
	fingerprintIdx := revokedPublicKeyByFileErrRE.SubexpIndex(idxSSHKeyFP)
	if fingerprintIdx > -1 {
		fingerprint = matches[fingerprintIdx]
	}

	var filePath string
	filePathIdx := revokedPublicKeyByFileErrRE.SubexpIndex(idxFilePath)
	if filePathIdx > -1 {
		filePath = matches[filePathIdx]
	}

	evt := revokedLogToAuditEvent(keyType, fingerprint, filePath, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func revokedLogToAuditEvent(keyType, fingerprint, filePath string, config *SshdProcessorer) *auditevent.AuditEvent {
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: common.UnknownUser,
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs":    common.UnknownUser,
			"userID":      common.UnknownUser,
			"pid":         config.pid,
			"keyType":     keyType,
			"fingerprint": fingerprint,
			"filePath":    filePath,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when

	return evt
}
