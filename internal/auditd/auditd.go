package auditd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
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
	// A zero time.Time means events are ignored.
	After time.Time

	// LogReader is the LogReader to read audit log lines from.
	LogReader LogReader

	// Logins receives common.RemoteUserLogin when a user logs in
	// remotely through a service like sshd.
	Logins <-chan common.RemoteUserLogin

	// EventW is the auditevent.EventWriter to write events to.
	EventW *auditevent.EventWriter
}

// TODO: Write documentation about creating a splunk query that shows
// only events after a user-start.
func (o *Auditd) Read(ctx context.Context) error {
	// TODO: Revisit these settings.
	const maxEventsInFlight = 1000
	const eventTimeout = 2 * time.Second
	reassembleAuditdEvents := make(chan reassembleAuditdEventResult)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: reassembleAuditdEvents,
		after:   o.After,
	})
	if err != nil {
		return fmt.Errorf("failed to create new auditd message resassembler - %w", err)
	}
	defer reassembler.Close()

	go func() {
		// This code comes from the go-libaudit example in:
		// cmd/auparse/auparse.go
		t := time.NewTicker(500 * time.Millisecond) //nolint
		defer t.Stop()

		for range t.C {
			if reassembler.Maintain() != nil {
				// Maintain returns non-nil error
				// if reassembler was closed.
				return
			}
		}
	}()

	parseAuditLogsDone := make(chan error, 1)
	go func() {
		parseAuditLogsDone <- parseAuditLogs(ctx, o.LogReader, reassembler)
	}()

	tracker := newSessionTracker(o.EventW)

	staleDataTicker := time.NewTicker(time.Minute)
	defer staleDataTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-staleDataTicker.C:
			aMinuteAgo := time.Now().Add(-time.Minute)

			tracker.deleteUsersWithoutLoginsBefore(aMinuteAgo)
			tracker.deleteRemoteUserLoginsBefore(aMinuteAgo)
		case remoteLogin := <-o.Logins:
			err = tracker.remoteLogin(remoteLogin)
			if err != nil {
				return fmt.Errorf("failed to handle remote user login - %w", err)
			}
		case err = <-parseAuditLogsDone:
			return fmt.Errorf("audit log parser exited unexpectedly with error - %w", err)
		case result := <-reassembleAuditdEvents:
			if result.err != nil {
				return fmt.Errorf("failed to reassemble auditd event - %w", result.err)
			}

			err = tracker.auditdEvent(result.event)
			if err != nil {
				return fmt.Errorf("failed to handle auditd event '%s' seq '%d' - %w",
					result.event.Type, result.event.Sequence, err)
			}
		}
	}
}

// parseAuditLogs parses audit log lines read from r and pushes them to reass
// until the provided context is marked as done.
func parseAuditLogs(ctx context.Context, r LogReader, reass *libaudit.Reassembler) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line := <-r.Lines():
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
				return fmt.Errorf("failed to parse auditd log line '%s' - %w",
					line, err)
			}

			reass.PushMessage(auditMsg)
		}
	}
}

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
			err: fmt.Errorf("failed to coalesce auditd messages - %w", err),
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

func newSessionTracker(eventWriter *auditevent.EventWriter) *sessionTracker {
	return &sessionTracker{
		sessIDsToUsers: make(map[string]*user),
		pidsToRULs:     make(map[int]common.RemoteUserLogin),
		eventWriter:    eventWriter,
	}
}

// sessionTracker tracks both remote user logins and auditd sessions,
// allowing us to correlate auditd events back to the credential
// a user used to authenticate.
type sessionTracker struct {
	// sessIDsToUsers contains active auditd sessions which may
	// or may not have a common.RemoteUserLogin associated with
	// them. It also acts as an auditd event cache.
	//
	// The map key is the auditd session ID and the value is
	// the corresponding user object.
	sessIDsToUsers map[string]*user

	// pidsToRULs caches remote user logins if an auditd
	// session has not started. This alleviates the race
	// between process-specific logs and audtid.
	//
	// The map key is the PID of a process responsible
	// for remote user logins and the value is the data
	// associated with the remote login.
	pidsToRULs map[int]common.RemoteUserLogin

	// eventWriter is the auditevent.EventWriter to write
	// the resulting audit event to.
	eventWriter *auditevent.EventWriter
}

func (o *sessionTracker) remoteLogin(rul common.RemoteUserLogin) error {
	err := rul.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate remote user login - %w", err)
	}

	// Check if there is an auditd session for this login.
	for _, u := range o.sessIDsToUsers {
		if u.srcPID == rul.PID {
			u.hasRUL = true
			u.login = rul

			return u.writeAndClearCache(o.eventWriter)
		}
	}

	_, hasIt := o.pidsToRULs[rul.PID]
	if hasIt {
		logger.Warnf("got a remote user login with a pid that already exists in the map (%d)",
			rul.PID)
	}

	o.pidsToRULs[rul.PID] = rul

	return nil
}

func (o *sessionTracker) auditdEvent(event *aucoalesce.Event) error {
	// TODO: Handle the "SystemAction" type (where session == "unset").
	//  ps: "unset" is a string.

	// Short-circuit if event is not associated with an audit session.
	// Processes like "cron" may run as a user, triggering an event
	// with no session ID. We want to skip those.
	if event.Session == "" || event.Session == "unset" {
		return nil
	}

	u, hasSession := o.sessIDsToUsers[event.Session]
	if hasSession {
		if u.hasRUL {
			// It looks like AUDIT_CRED_DISP indicates the
			// canonical end of a user session - but, there is
			// also AUDIT_USER_END, which occurs just before.
			if event.Type == auparse.AUDIT_CRED_DISP {
				defer delete(o.sessIDsToUsers, event.Session)
			}

			err := u.writeAndClearCache(o.eventWriter)
			if err != nil {
				return fmt.Errorf("failed to write cached events for user '%s' - %w",
					u.login.CredUserID, err)
			}

			return o.eventWriter.Write(u.toAuditEvent(event))
		}
	} else {
		srcPID, err := strconv.Atoi(event.Process.PID)
		if err != nil {
			return fmt.Errorf("failed to parse auditd session init event pid ('%s') - %w",
				event.Process.PID, err)
		}

		u = &user{
			added:  time.Now(),
			srcPID: srcPID,
		}

		if rul, hasRUL := o.pidsToRULs[srcPID]; hasRUL {
			delete(o.pidsToRULs, srcPID)

			u.hasRUL = true
			u.login = rul

			o.sessIDsToUsers[event.Session] = u

			return o.eventWriter.Write(u.toAuditEvent(event))
		}
	}

	u.cached = append(u.cached, event)
	o.sessIDsToUsers[event.Session] = u

	return nil
}

func (o *sessionTracker) deleteUsersWithoutLoginsBefore(t time.Time) {
	for id, u := range o.sessIDsToUsers {
		if !u.hasRUL && u.added.Before(t) {
			delete(o.sessIDsToUsers, id)
		}
	}
}

func (o *sessionTracker) deleteRemoteUserLoginsBefore(t time.Time) {
	for pid, userLogin := range o.pidsToRULs {
		if userLogin.Source.LoggedAt.Before(t) {
			delete(o.pidsToRULs, pid)
		}
	}
}

type user struct {
	added  time.Time
	srcPID int
	hasRUL bool
	login  common.RemoteUserLogin
	cached []*aucoalesce.Event
}

func (o *user) toAuditEvent(ae *aucoalesce.Event) *auditevent.AuditEvent {
	outcome := auditevent.OutcomeFailed
	switch ae.Result {
	case "success":
		outcome = auditevent.OutcomeSucceeded
	case "fail":
		// No-op.
	}

	// TODO: Subjects should contain the user's login ID.
	//  Do we need to assign it to the map again to be sure?
	subjectsCopy := make(map[string]string, len(o.login.Source.Subjects))
	for k, v := range o.login.Source.Subjects {
		subjectsCopy[k] = v
	}

	evt := auditevent.NewAuditEvent(
		common.ActionUserAction,
		o.login.Source.Source,
		outcome,
		subjectsCopy,
		"auditd",
	).WithTarget(o.login.Source.Target)

	evt.LoggedAt = ae.Timestamp
	evt.Metadata.AuditID = ae.Session

	// TODO: Talk with Ozz about this. The metadata fields appear to
	//  be OS-specific (git grep "executed" in go-libaudit).
	evt.Metadata.Extra = map[string]any{
		"action": ae.Summary.Action,
		"how":    ae.Summary.How,
		"object": ae.Summary.Object,
	}

	return evt
}

func (o *user) writeAndClearCache(writer *auditevent.EventWriter) error {
	if len(o.cached) == 0 {
		return nil
	}

	for i := range o.cached {
		err := writer.Write(o.toAuditEvent(o.cached[i]))
		if err != nil {
			return err
		}
	}

	o.cached = nil

	return nil
}
