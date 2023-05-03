package sshd

import (
	"fmt"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func rootLoginRefused(config *SshdProcessorer) error {
	matches := rootLoginRefusedRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got rootLoginRefused log with no string sub-matches")
		return nil
	}

	var source string
	sourceIdx := rootLoginRefusedRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	var port string
	portIdx := rootLoginRefusedRE.SubexpIndex(idxLoginPort)
	if portIdx > -1 {
		port = matches[portIdx]
	}

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: source,
			Extra: map[string]any{
				"port": port,
			},
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": "root",
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
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func badOwnerOrModesForHostFile(config *SshdProcessorer) error {
	matches := badOwnerOrModesForHostFileRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got badOwnerOrModesForHostFile log with no string sub-matches")
		return nil
	}

	var username string
	usernameIdx := badOwnerOrModesForHostFileRE.SubexpIndex(idxLoginUserName)
	if usernameIdx > -1 {
		username = matches[usernameIdx]
	}

	var filePath string
	filePathIdx := badOwnerOrModesForHostFileRE.SubexpIndex(idxFilePath)
	if filePathIdx > -1 {
		filePath = matches[filePathIdx]
	}

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: common.UnknownAddr,
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": username,
			"userID":   common.UnknownUser,
			"pid":      config.pid,
			"filePath": filePath,
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       config.nodeName,
		"machine-id": config.machineID,
	})

	evt.LoggedAt = config.when

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

//nolint:dupl // No lint
func maxAuthAttemptsExceeded(config *SshdProcessorer) error {
	matches := maxAuthAttemptsExceededRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got maxAuthAttemptsExceeded log with no string sub-matches")
		return nil
	}

	var username string
	usernameIdx := maxAuthAttemptsExceededRE.SubexpIndex(idxLoginUserName)
	if usernameIdx > -1 {
		username = matches[usernameIdx]
	}

	var source string
	sourceIdx := maxAuthAttemptsExceededRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	var port string
	portIdx := maxAuthAttemptsExceededRE.SubexpIndex(idxLoginPort)
	if portIdx > -1 {
		port = matches[portIdx]
	}

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: source,
			Extra: map[string]any{
				"port": port,
			},
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": username,
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
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

//nolint:dupl // No lint
func failedPasswordAuth(config *SshdProcessorer) error {
	matches := failedPasswordAuthRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got failedPasswordAuth log with no string sub-matches")
		return nil
	}

	var username string
	usernameIdx := failedPasswordAuthRE.SubexpIndex(idxLoginUserName)
	if usernameIdx > -1 {
		username = matches[usernameIdx]
	}

	var source string
	sourceIdx := failedPasswordAuthRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	var port string
	portIdx := failedPasswordAuthRE.SubexpIndex(idxLoginPort)
	if portIdx > -1 {
		port = matches[portIdx]
	}

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: source,
			Extra: map[string]any{
				"port": port,
			},
		},
		auditevent.OutcomeFailed,
		map[string]string{
			"loggedAs": username,
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
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}
