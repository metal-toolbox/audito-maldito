package sshd

import (
	"fmt"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

// userTypeLogAuditFn attempts to find an audit event generator function
// that corresponds to the provided "User-type" OpenSSH log line.
//
// Refer to OpenSSH regex starting with "user" for more information.
//
// nil is returned if no corresponding audit function is available.
func userTypeLogAuditFn(config *SshdProcessorer) func(*SshdProcessorer) error {
	switch {
	case notInAllowUsersRE.MatchString(config.logEntry):
		return processNotInAllowUsersEntry
	case userNonExistentShellRE.MatchString(config.logEntry):
		return userNonExistentShell
	case userNonExecutableShellRE.MatchString(config.logEntry):
		return userNonExecutableShell
	case userInDenyUsersRE.MatchString(config.logEntry):
		return userInDenyUsers
	case userNotInAnyGroupRE.MatchString(config.logEntry):
		return userNotInAnyGroup
	case userGroupInDenyGroupsRE.MatchString(config.logEntry):
		return userGroupInDenyGroups
	case userGroupNotListedInAllowGroupsRE.MatchString(config.logEntry):
		return userGroupNotListedInAllowGroups
	default:
		return nil
	}
}

func processNotInAllowUsersEntry(config *SshdProcessorer) error {
	matches := notInAllowUsersRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got login entry with no regular expression matches for not-in-allow-users")
		return nil
	}

	var username string
	userIdx := notInAllowUsersRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var source string
	sourceIdx := notInAllowUsersRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := userLogToAuditEvent(username, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userNonExistentShell(config *SshdProcessorer) error {
	matches := userNonExistentShellRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userNonExistentShell log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userNonExistentShellRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var shell string
	shellIdx := userNonExistentShellRE.SubexpIndex(idxShell)
	if shellIdx > -1 {
		shell = matches[shellIdx]
	}

	evt := userLogToAuditEvent(username, common.UnknownAddr, config)
	evt.Metadata.Extra["shell"] = shell

	evt.LoggedAt = config.when
	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userNonExecutableShell(config *SshdProcessorer) error {
	matches := userNonExecutableShellRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userNonExecutableShell log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userNonExecutableShellRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var shell string
	shellIdx := userNonExecutableShellRE.SubexpIndex(idxShell)
	if shellIdx > -1 {
		shell = matches[shellIdx]
	}

	evt := userLogToAuditEvent(username, common.UnknownAddr, config)
	evt.Metadata.Extra["shell"] = shell

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userInDenyUsers(config *SshdProcessorer) error {
	matches := userInDenyUsersRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userInDenyUsers log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userInDenyUsersRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var source string
	sourceIdx := userInDenyUsersRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := userLogToAuditEvent(username, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userNotInAnyGroup(config *SshdProcessorer) error {
	matches := userNotInAnyGroupRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userNotInAnyGroup log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userNotInAnyGroupRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var source string
	sourceIdx := userNotInAnyGroupRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := userLogToAuditEvent(username, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userGroupInDenyGroups(config *SshdProcessorer) error {
	matches := userGroupInDenyGroupsRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userGroupInDenyGroups log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userGroupInDenyGroupsRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var source string
	sourceIdx := userGroupInDenyGroupsRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := userLogToAuditEvent(username, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userGroupNotListedInAllowGroups(config *SshdProcessorer) error {
	matches := userGroupNotListedInAllowGroupsRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got userGroupNotListedInAllowGroups log with no string sub-matches")
		return nil
	}

	var username string
	userIdx := userGroupNotListedInAllowGroupsRE.SubexpIndex(idxLoginUserName)
	if userIdx > -1 {
		username = matches[userIdx]
	}

	var source string
	sourceIdx := userGroupNotListedInAllowGroupsRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := userLogToAuditEvent(username, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func userLogToAuditEvent(username string, source string, config *SshdProcessorer) *auditevent.AuditEvent {
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: source,
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

	return evt
}
