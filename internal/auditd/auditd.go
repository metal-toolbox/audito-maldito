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
func (o *Auditd) Read(ctx context.Context) error {
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
		eventProcessorDone <- processAuditdEvents(o.Source, reassembler)
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

			eventer.deleteCachedSessionsBefore(aMinuteAgo)
			eventer.deleteRemoteUserLoginsBefore(aMinuteAgo)
			eventer.deletePIDsToSessIDsBefore(aMinuteAgo)
		case remoteLogin := <-o.Logins:
			err = eventer.remoteLogin(remoteLogin)
			if err != nil {
				return fmt.Errorf("failed to add remote user login - %w", err)
			}
		case events := <-auditdEvents:
			// TODO: Maybe CoalesceMessages and ResolveIDs should
			//  be executed on a different Go routine?
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

func processAuditdEvents(r io.Reader, reass *libaudit.Reassembler) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		auditMsg, err := auparse.ParseLogLine(scanner.Text())
		if err != nil {
			return err
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
		sessIDsToUsers:  make(map[string]user),
		sessIDsToEvents: make(map[string]*sessionEventCache),
		pidsToSessIDs:   make(map[int]sessionIDCache),
		pidsToRULs:      make(map[int]common.RemoteUserLogin),
		eventWriter:     eventWriter,
	}
}

// auditdEventer tracks both remote user logins and auditd user_starts,
// allowing us to correlate auditd events back to the credential a user
// used to authenticate.
type auditdEventer struct {
	// sessIDsToUsers contains active auditd sessions that have
	// been correlated to remote logins.
	//
	// The map key is the auditd session ID and the value is
	// the corresponding user object.
	sessIDsToUsers map[string]user

	// sessIDsToEvents caches auditd events until a remote user
	// login occurs.
	//
	// The map key is the auditd session ID and the value is
	// a sessionEventCache.
	sessIDsToEvents map[string]*sessionEventCache

	// pidsToSessIDs caches the PID of a remote user login
	// process and its auditd session ID when there is no
	// corresponding remote user login. This alleviates the
	// race between process-specific logs and audtid.
	//
	// The map key is the PID of a process responsible for
	// remote user logins and the value is the auditd
	// sessions ID.
	pidsToSessIDs map[int]sessionIDCache

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

func (o *auditdEventer) remoteLogin(login common.RemoteUserLogin) error {
	err := login.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate remote user login - %w", err)
	}

	_, hasIt := o.pidsToRULs[login.PID]
	if hasIt {
		logger.Warnf("got a remote user login with a pid that already exists in the map (%d)",
			login.PID)
	}

	existingSessionID, hasSession := o.pidsToSessIDs[login.PID]
	if hasSession {
		delete(o.pidsToSessIDs, login.PID)

		u := user{
			login: login,
		}

		o.sessIDsToUsers[existingSessionID.id] = u

		cache, hasCache := o.sessIDsToEvents[existingSessionID.id]
		if hasCache {
			delete(o.sessIDsToEvents, existingSessionID.id)

			return writeCachedUserEvents(o.eventWriter, u, cache.aucoalesceEvents)
		}
	} else {
		o.pidsToRULs[login.PID] = login
	}

	return nil
}

func writeCachedUserEvents(writer *auditevent.EventWriter, u user, events []*aucoalesce.Event) error {
	numEvents := len(events)
	if numEvents == 0 {
		return nil
	}

	for i := numEvents - 1; i > -1; i-- {
		err := writer.Write(userActionAuditEvent(u, events[i]))
		if err != nil {
			return err
		}
	}

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

	switch event.Type {
	case auparse.AUDIT_USER_START:
		log.Printf("TODO: user start")
		return o.auditdLogin(event)
	case auparse.AUDIT_USER_END:
		log.Printf("TODO: user end")
		return o.auditdLogout(event)
	default:
		log.Printf("TODO: other event - %s", event.Summary)

		u, loggedIn := o.sessIDsToUsers[event.Session]
		if loggedIn {
			return o.eventWriter.Write(userActionAuditEvent(u, event))
		}

		cache, hasCache := o.sessIDsToEvents[event.Session]
		if !hasCache {
			cache = newSessionEventCache(event.Timestamp)
		}

		cache.aucoalesceEvents = append(cache.aucoalesceEvents, event)

		if !hasCache {
			o.sessIDsToEvents[event.Session] = cache
		}

		return nil
	}
}

func (o *auditdEventer) auditdLogin(userStart *aucoalesce.Event) error {
	pid, err := strconv.Atoi(userStart.Process.PID)
	if err != nil {
		logger.Errorf("failed to convert pid string to int from auditd user-start ('%s') - %s",
			userStart.Process.PID, err)
		return nil
	}

	remoteUserLogin, hasIt := o.pidsToRULs[pid]
	if hasIt {
		delete(o.pidsToRULs, pid)

		o.sessIDsToUsers[userStart.Session] = user{
			login: remoteUserLogin,
		}
	} else {
		o.pidsToSessIDs[pid] = sessionIDCache{
			createdAt: time.Now(),
			id:        userStart.Session,
		}
	}

	return nil
}

func (o *auditdEventer) auditdLogout(userEnd *aucoalesce.Event) error {
	u, hasIt := o.sessIDsToUsers[userEnd.Session]
	if hasIt {
		delete(o.sessIDsToUsers, userEnd.Session)

		return o.eventWriter.Write(userActionAuditEvent(u, userEnd))
	}

	return nil
}

func (o *auditdEventer) deleteCachedSessionsBefore(t time.Time) {
	for id, cache := range o.sessIDsToEvents {
		if cache.createdAt.Before(t) {
			delete(o.sessIDsToEvents, id)
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

func (o *auditdEventer) deletePIDsToSessIDsBefore(t time.Time) {
	for pid, cache := range o.pidsToSessIDs {
		if cache.createdAt.Before(t) {
			delete(o.pidsToSessIDs, pid)
		}
	}
}

func newSessionEventCache(createdAt time.Time) *sessionEventCache {
	return &sessionEventCache{
		createdAt: createdAt,
	}
}

type sessionEventCache struct {
	createdAt        time.Time
	aucoalesceEvents []*aucoalesce.Event
}

type sessionIDCache struct {
	createdAt time.Time
	id        string
}

type user struct {
	login common.RemoteUserLogin
}

func userActionAuditEvent(u user, ae *aucoalesce.Event) *auditevent.AuditEvent {
	outcome := auditevent.OutcomeFailed
	switch ae.Result {
	case "success":
		outcome = auditevent.OutcomeSucceeded
	case "fail":
		// No-op.
	}

	// TODO: Subjects should contain the user's login ID.
	//  Do we need to assign it to the map again to be sure?
	subjectsCopy := make(map[string]string, len(u.login.Source.Subjects))
	for k, v := range u.login.Source.Subjects {
		subjectsCopy[k] = v
	}

	evt := auditevent.NewAuditEvent(
		common.ActionUserAction,
		u.login.Source.Source,
		outcome,
		subjectsCopy,
		"auditd",
	).WithTarget(u.login.Source.Target)

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
