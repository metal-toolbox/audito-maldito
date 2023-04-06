package auditd

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/auditd/sessiontracker"
	"github.com/metal-toolbox/audito-maldito/internal/common"
)

// libaudit variables.
const (
	maxEventsInFlight        = 1000
	eventTimeout             = 2 * time.Second
	reassemblerInterval      = 500 * time.Millisecond
	staleDataCleanupInterval = 1 * time.Minute
)

var logger *zap.SugaredLogger

func SetLogger(l *zap.SugaredLogger) {
	logger = l
}

// Auditd enables correlation of remote user logins (and the credential they
// used to log in with, such as a SSH certificate) and Linux audit events.
type Auditd struct {
	// After filters audit events prior to a particular point in time.
	// For example, using time.Now means all events that occurred
	// before time.Now will be ignored.
	//
	// A zero time.Time means no events are ignored.
	After time.Time

	// Audits receives audit log lines from one or more audit files.
	Audits <-chan string

	// Logins receives common.RemoteUserLogin when a user logs in
	// remotely through a service like sshd.
	Logins <-chan common.RemoteUserLogin

	// EventW is the auditevent.EventWriter to write events to.
	EventW *auditevent.EventWriter

	Health *common.Health
}

// TODO: Write documentation about creating a splunk query that shows
// only events after a user-start.
func (o *Auditd) Read(ctx context.Context) error {
	reassembleAuditdEvents := make(chan reassembleAuditdEventResult)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: reassembleAuditdEvents,
		after:   o.After,
	})
	if err != nil {
		return fmt.Errorf("failed to create new auditd message resassembler - %w", err)
	}
	// TODO: Calling reassembler.Close is not safe because
	// it then calls our reassemblerCB, which then tries to
	// write to the reassembleAuditdEvents channel - which
	// no Go routine will be listening to it. This is super
	// unclear from the Close documentation.
	// defer reassembler.Close()

	go maintainReassemblerLoop(ctx, reassembler, reassemblerInterval)

	parseAuditLogsDone := make(chan error, 1)
	go func() {
		parseAuditLogsDone <- parseAuditLogs(ctx, o.Audits, reassembler)
	}()

	tracker := sessiontracker.NewSessionTracker(o.EventW, logger)

	staleDataTicker := time.NewTicker(staleDataCleanupInterval)
	defer staleDataTicker.Stop()

	o.Health.OnReady()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-staleDataTicker.C:
			aMinuteAgo := time.Now().Add(-staleDataCleanupInterval)

			tracker.DeleteUsersWithoutLoginsBefore(aMinuteAgo)
			tracker.DeleteRemoteUserLoginsBefore(aMinuteAgo)
		case remoteLogin := <-o.Logins:
			err = tracker.RemoteLogin(remoteLogin)
			if err != nil {
				return fmt.Errorf("failed to handle remote user login - %w", err)
			}
		case err = <-parseAuditLogsDone:
			return fmt.Errorf("audit log parser exited unexpectedly with error - %w", err)
		case result := <-reassembleAuditdEvents:
			if result.err != nil {
				return fmt.Errorf("failed to reassemble auditd event - %w", result.err)
			}

			err = tracker.AuditdEvent(result.event)
			if err != nil {
				return fmt.Errorf("failed to handle auditd event '%s' seq '%d' - %w",
					result.event.Type, result.event.Sequence, err)
			}
		}
	}
}

// maintainReassemblerLoop calls libaudit.Reassembler.Maintain in a loop
// at an interval specified by d.
func maintainReassemblerLoop(ctx context.Context, reassembler *libaudit.Reassembler, d time.Duration) {
	// This code comes from the go-libaudit example in:
	// cmd/auparse/auparse.go
	t := time.NewTicker(d)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if reassembler.Maintain() != nil {
				// Maintain returns non-nil error
				// if reassembler was closed.
				return
			}
		}
	}
}

// parseAuditLogs parses audit log lines read from lines and pushes them
// to reass until the provided context is marked as done.
func parseAuditLogs(ctx context.Context, lines <-chan string, reass *libaudit.Reassembler) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line := <-lines:
			if line == "" {
				// Parsing an empty line results in this error:
				//    invalid audit message header
				//
				// I ran into this while writing unit tests,
				// as several auditd string literal constants
				// started with a new line.
				continue
			}

			auditMsg, err := auparse.ParseLogLine(line)
			if err != nil {
				return &parseAuditLogsError{
					message: fmt.Sprintf("failed to parse auditd log line '%s' - %s",
						line, err),
					inner: err,
				}
			}

			reass.PushMessage(auditMsg)
		}
	}
}

var _ libaudit.Stream = &reassemblerCB{}

// reassemblerCB implements the libaudit.Stream interface.
type reassemblerCB struct {
	ctx     context.Context //nolint
	results chan<- reassembleAuditdEventResult
	after   time.Time
}

func (s *reassemblerCB) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		select {
		case <-s.ctx.Done():
		case s.results <- reassembleAuditdEventResult{
			err: &reassemblerCBError{
				message: fmt.Sprintf("failed to coalesce audit messages - %s", err),
				inner:   err,
			},
		}:
		}

		return
	}

	if event.Timestamp.Before(s.after) {
		return
	}

	aucoalesce.ResolveIDs(event)

	select {
	case <-s.ctx.Done():
	case s.results <- reassembleAuditdEventResult{event: event}:
	}
}

func (s *reassemblerCB) EventsLost(count int) {
	logger.Errorf("lost %d auditd events during reassembly", count)
}

type reassembleAuditdEventResult struct {
	event *aucoalesce.Event
	err   error
}
