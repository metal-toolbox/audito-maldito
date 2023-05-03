package sshd

import (
	"fmt"

	"github.com/metal-toolbox/auditevent"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func nastyPTRRecord(config *SshdProcessorer) error {
	matches := nastyPTRRecordRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got nastyPTRRecord log with no string sub-matches")
		return nil
	}

	var dnsName string
	recordIdx := nastyPTRRecordRE.SubexpIndex(idxDNSName)
	if recordIdx > -1 {
		dnsName = matches[recordIdx]
	}

	var source string
	sourceIdx := nastyPTRRecordRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := dnsLogToAuditEvent(dnsName, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func reverseMappingCheckFailed(config *SshdProcessorer) error {
	matches := reverseMappingCheckFailedRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got reverseMappingCheckFailed log with no string sub-matches")
		return nil
	}

	var dnsName string
	recordIdx := reverseMappingCheckFailedRE.SubexpIndex(idxDNSName)
	if recordIdx > -1 {
		dnsName = matches[recordIdx]
	}

	var source string
	sourceIdx := reverseMappingCheckFailedRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := dnsLogToAuditEvent(dnsName, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func doesNotMapBackToAddr(config *SshdProcessorer) error {
	matches := doesNotMapBackToAddrRE.FindStringSubmatch(config.logEntry)
	if matches == nil {
		logger.Infoln("got doesNotMapBackToAddr log with no string sub-matches")
		return nil
	}

	var dnsName string
	recordIdx := doesNotMapBackToAddrRE.SubexpIndex(idxDNSName)
	if recordIdx > -1 {
		dnsName = matches[recordIdx]
	}

	var source string
	sourceIdx := doesNotMapBackToAddrRE.SubexpIndex(idxLoginSource)
	if sourceIdx > -1 {
		source = matches[sourceIdx]
	}

	evt := dnsLogToAuditEvent(dnsName, source, config)

	if err := config.eventW.Write(evt); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

func dnsLogToAuditEvent(dnsName string, source string, config *SshdProcessorer) *auditevent.AuditEvent {
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: source,
			Extra: map[string]any{
				"dns": dnsName,
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

	return evt
}
