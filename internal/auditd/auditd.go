package auditd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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

type Auditd struct {
	Source io.Reader
	Logins <-chan common.RemoteUserLogin
	EventW *auditevent.EventWriter
}

// TODO: Should this code close the auditd reader on behalf of the caller?
//
// TODO: Write documentation about creating a splunk query that shows
//  only events after a user-start.
func (o *Auditd) Read(ctx context.Context) error {
	// TODO: Revisit these settings.
	const maxEventsInFlight = 1000
	const eventTimeout = 2 * time.Second
	auditdEvents := make(chan []*auparse.AuditMessage)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:  ctx,
		msgs: auditdEvents,
	})
	if err != nil {
		return fmt.Errorf("failed to create new auditd message resassembler - %w", err)
	}
	defer reassembler.Close()

	go func() {
		// This code comes from the go-libaudit example in:
		// cmd/auparse/auparse.go
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()

		for range t.C {
			if reassembler.Maintain() != nil {
				// Maintain returns non-nil error
				// if reassembler was closed.
				return
			}
		}
	}()

	eventProcessorDone := make(chan error, 1)

	go func() {
		eventProcessorDone <- processAuditdLogLines(o.Source, reassembler)
	}()

	eventer := newAuditdEventer(o.EventW)

	staleDataTicker := time.NewTicker(time.Minute)
	defer staleDataTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-eventProcessorDone:
			if err != nil {
				return fmt.Errorf("auditd event processer exited unexpectedly with error - %w", err)
			}

			return errors.New("auditd event processor exited unexpectedly with nil error")
		case <-staleDataTicker.C:
			aMinuteAgo := time.Now().Add(-time.Minute)

			eventer.deleteUsersWithoutLoginsBefore(aMinuteAgo)
			eventer.deleteRemoteUserLoginsBefore(aMinuteAgo)
		case remoteLogin := <-o.Logins:
			err = eventer.remoteLogin(remoteLogin)
			if err != nil {
				return fmt.Errorf("failed to handle remote user login - %w", err)
			}
		case events := <-auditdEvents:
			// TODO: Maybe CoalesceMessages and ResolveIDs should
			//  be executed on a different Go routine?
			// TODO: yes.
			auditdEvent, err := aucoalesce.CoalesceMessages(events)
			if err != nil {
				return fmt.Errorf("failed to coalesce auditd messages - %w", err)
			}

			aucoalesce.ResolveIDs(auditdEvent)

			err = eventer.handleAuditdEvent(auditdEvent)
			if err != nil {
				return fmt.Errorf("failed to handle auditd event '%s' - %w",
					auditdEvent.Type, err)
			}
		}
	}
}

func processAuditdLogLines(r io.Reader, reass *libaudit.Reassembler) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
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

	return scanner.Err()
}

type reassemblerCB struct {
	ctx  context.Context
	msgs chan<- []*auparse.AuditMessage
}

func (s *reassemblerCB) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	select {
	case <-s.ctx.Done():
	case s.msgs <- msgs:
	}
}

func (s *reassemblerCB) EventsLost(count int) {
	logger.Errorf("lost %d auditd events during reassembly", count)
}

func newAuditdEventer(eventWriter *auditevent.EventWriter) *auditdEventer {
	return &auditdEventer{
		sessIDsToUsers: make(map[string]*user),
		pidsToRULs:     make(map[int]common.RemoteUserLogin),
		eventWriter:    eventWriter,
	}
}

// auditdEventer tracks both remote user logins and auditd user_starts,
// allowing us to correlate auditd events back to the credential a user
// used to authenticate.
type auditdEventer struct {
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
	//
	// TODO: Should we execute writes w/ a timeout?
	//  Had a deadlock in testing because the Go
	//  routine executes the writes directly.
	eventWriter *auditevent.EventWriter
}

func (o *auditdEventer) remoteLogin(rul common.RemoteUserLogin) error {
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

func (o *auditdEventer) handleAuditdEvent(event *aucoalesce.Event) error {
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

func (o *auditdEventer) deleteUsersWithoutLoginsBefore(t time.Time) {
	for id, u := range o.sessIDsToUsers {
		if !u.hasRUL && u.added.Before(t) {
			delete(o.sessIDsToUsers, id)
		}
	}
}

func (o *auditdEventer) deleteRemoteUserLoginsBefore(t time.Time) {
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
