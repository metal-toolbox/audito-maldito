package sessiontracker

import (
	"fmt"
	"strconv"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

// Implement Auditor interface.
var _ Auditor = &sessionTracker{}

// NewSessionTracker returns a new instance of a sessionTracker.
func NewSessionTracker(eventWriter *auditevent.EventWriter, l *zap.SugaredLogger) *sessionTracker {
	if l == nil {
		l = zap.NewNop().Sugar()
	}

	return &sessionTracker{
		sessIDsToUsers: common.NewGenericSyncMap[string, *user](),
		pidsToRULs:     common.NewGenericSyncMap[int, common.RemoteUserLogin](),
		eventWriter:    eventWriter,
		l:              l,
	}
}

// sessionTracker tracks both remote user logins and auditd sessions,
// allowing us to correlate auditd events back to the credential
// a user used to authenticate.
//
// This struct's methods are not thread-safe (i.e., they are intended
// to be called by a single Go routine).
type sessionTracker struct {
	// sessIDsToUsers contains active auditd sessions which may
	// or may not have a common.RemoteUserLogin associated with
	// them. It also acts as an auditd event cache.
	//
	// The map key is the auditd session ID and the value is
	// the corresponding user object.
	sessIDsToUsers *common.GenericSyncMap[string, *user]

	// pidsToRULs caches remote user logins if an auditd
	// session has not started. This alleviates the race
	// between process-specific logs and audtid.
	//
	// The map key is the PID of a process responsible
	// for remote user logins and the value is the data
	// associated with the remote login.
	pidsToRULs *common.GenericSyncMap[int, common.RemoteUserLogin]

	// eventWriter is the auditevent.EventWriter to write
	// the resulting audit event to.
	eventWriter *auditevent.EventWriter

	// l is the logger to use.
	l *zap.SugaredLogger
}

func (o *sessionTracker) RemoteLogin(rul common.RemoteUserLogin) error {
	var debugLogger *zap.SugaredLogger
	if o.l.Level().Enabled(zap.DebugLevel) {
		debugLogger = o.l.With("RemoteUserLogin", rul)
		debugLogger.Debugln("new remote user login")
	}

	err := rul.Validate()
	if err != nil {
		return &SessionTrackerError{
			remoteLoginFail: true,
			message:         fmt.Sprintf("failed to validate remote user login - %s", err),
			inner:           err,
		}
	}

	// Check if there is an auditd session for this login.
	var found bool
	var writeErr error
	o.sessIDsToUsers.Iterate(func(asi string, u *user) bool {
		if u.srcPID == rul.PID {
			if debugLogger != nil {
				debugLogger.With(
					"auditSessionID", asi,
					"auditSessionStartTime", u.added,
					"numCachedAuditEvents", len(u.cached),
					"hasRUL", u.hasRUL).
					Debugln("found existing audit session for remote user login")
			}

			// We modify the user object in-place, in this section
			// since it's thread-safe (i.e., it's a pointer).
			u.setRemoteUserLoginInfo(rul)

			found = true
			writeErr = u.writeAndClearCache(o.eventWriter)
			// stop iteration
			return false
		}

		return true
	})

	if found {
		// We found an audit session for this login, and the
		// user object has been modified in-place. We can
		// return early.
		return writeErr
	}

	if debugLogger != nil {
		debugLogger.Debugln("no matching audit session found")
	}

	_, hasIt := o.pidsToRULs.Load(rul.PID)
	if hasIt {
		o.l.Warnf("got a remote user login with a pid that already exists in the map (%d)",
			rul.PID)
	}

	o.pidsToRULs.Store(rul.PID, rul)

	return nil
}

func (o *sessionTracker) AuditdEvent(event *aucoalesce.Event) error {
	// TODO: Handle the "SystemAction" type (where session == "unset").
	//  ps: "unset" is a string.

	// Short-circuit if event is not associated with an audit session.
	// Processes like "cron" may run as a user, triggering an event
	// with no session ID. We want to skip those.
	if event.Session == "" || event.Session == "unset" {
		return nil
	}

	debugLogger := o.l.With(
		"auditEvent", *event,
		"auditEventType", event.Type.String(),
		"auditSessionID", event.Session)
	debugLogger.Debugln("new audit event")

	if o.sessIDsToUsers.Has(event.Session) {
		return o.auditEventWithSession(event, debugLogger)
	}

	return o.auditEventWithoutSession(event, debugLogger)
}

// auditEventWithSession handles an audit event that is associated with
// an audit session. If the user object associated with the session
// already has remote user login information, the event is written to the
// audit event writer. Otherwise, the event is cached in the user object.
//
// Note that this is all done within a lock on the user object. So it's
// thread-safe. However, recall the WithLockedValueDo method holds
// the lock for the duration of the callback. So this method should
// return quickly and shouldn't call any other locking methods on the
// sessionTracker.
func (o *sessionTracker) auditEventWithSession(event *aucoalesce.Event, debugLogger *zap.SugaredLogger) error {
	return o.sessIDsToUsers.WithLockedValueDo(event.Session, func(u *user) error {
		debugLogger.With(
			"auditSessionStartTime", u.added,
			"numCachedAuditEvents", len(u.cached),
			"hasRUL", u.hasRemoteUserLoginInfo()).
			Debugln("found existing audit session for audit event")

		if !u.hasRemoteUserLoginInfo() {
			debugLogger.Debugln("caching audit event")

			// Cache the event if the audit session does not have
			// any associated common.RemoteUserLogin object.
			u.cached = append(u.cached, event)

			return nil
		}

		// It looks like AUDIT_CRED_DISP indicates the
		// canonical end of a user session - but, there is
		// also AUDIT_USER_END, which occurs just before.
		if event.Type == auparse.AUDIT_CRED_DISP {
			defer o.sessIDsToUsers.DeleteUnsafe(event.Session)
		}

		err := u.writeAndClearCache(o.eventWriter)
		if err != nil {
			return &SessionTrackerError{
				auditEventFail: true,
				message: fmt.Sprintf("failed to write cached events for user '%s' - %s",
					u.login.CredUserID, err),
				inner: err,
			}
		}

		err = o.eventWriter.Write(u.toAuditEvent(event))
		if err != nil {
			return &SessionTrackerError{
				auditEventFail: true,
				message:        err.Error(),
				inner:          err,
			}
		}

		return nil
	})
}

func (o *sessionTracker) auditEventWithoutSession(event *aucoalesce.Event, debugLogger *zap.SugaredLogger) error {
	// Create a new audit session.

	if event.Type != auparse.AUDIT_LOGIN {
		debugLogger.Debugln("skipping creation of new audit session for audit event")

		// It appears AUDIT_LOGIN indicates the
		// canonical start of a user session.
		// At least, it is the event type
		// associated with a user-specific
		// sshd process.
		return nil
	}

	debugLogger.Debugln("creating new audit session for audit event")

	srcPID, err := strconv.Atoi(event.Process.PID)
	if err != nil {
		return &SessionTrackerError{
			auditEventFail: true,
			message: fmt.Sprintf("failed to parse audit session init event pid for session id '%s' ('%s') - %s",
				event.Session, event.Process.PID, err),
			inner: err,
		}
	}

	procArgs := event.Process.Args

	u := &user{
		added:    time.Now(),
		srcPID:   srcPID,
		procArgs: procArgs,
	}

	if o.pidsToRULs.Has(srcPID) {
		return o.pidsToRULs.WithLockedValueDo(srcPID, func(rul common.RemoteUserLogin) error {
			debugLogger.Debugln("found existing remote user login for new audit session")

			o.pidsToRULs.DeleteUnsafe(srcPID)

			u.setRemoteUserLoginInfo(rul)

			o.sessIDsToUsers.Store(event.Session, u)

			err = o.eventWriter.Write(u.toAuditEvent(event))
			if err != nil {
				return &SessionTrackerError{
					auditEventFail: true,
					message:        err.Error(),
					inner:          err,
				}
			}

			return nil
		})
	}

	debugLogger.Debugln("no existing remote user login for new audit session")
	debugLogger.Debugln("caching audit event")

	// Cache the event if the audit session does not have
	// any associated common.RemoteUserLogin object.
	u.cached = append(u.cached, event)

	o.sessIDsToUsers.Store(event.Session, u)
	return nil
}

func (o *sessionTracker) DeleteUsersWithoutLoginsBefore(t time.Time) {
	var debugLogger *zap.SugaredLogger
	if o.l.Level().Enabled(zap.DebugLevel) {
		debugLogger = o.l.With(
			"cacheCleanup", "deleteUsersWithoutLoginsBefore",
			"before", t.String())
	}

	o.sessIDsToUsers.Iterate(func(id string, u *user) bool {
		if !u.hasRUL && u.added.Before(t) {
			if debugLogger != nil {
				debugLogger.With(
					"auditSessionID", id,
					"auditSessionStartTime", u.added.String()).
					Debugln("removing unused audit session")
			}

			// this is fine as the function is called from within
			// the Iterate function, which is safe for concurrent
			// access. The lock is already held.
			o.sessIDsToUsers.DeleteUnsafe(id)
		}
		return true
	})
}

func (o *sessionTracker) DeleteRemoteUserLoginsBefore(t time.Time) {
	var debugLogger *zap.SugaredLogger
	if o.l.Level().Enabled(zap.DebugLevel) {
		debugLogger = o.l.With(
			"cacheCleanup", "deleteRemoteUserLoginsBefore",
			"before", t.String())
	}

	o.pidsToRULs.Iterate(func(pid int, userLogin common.RemoteUserLogin) bool {
		if userLogin.Source.LoggedAt.Before(t) {
			if debugLogger != nil {
				debugLogger.With(
					"pid", pid,
					"source", *userLogin.Source).
					Debugln("removing unused remote user login")
			}

			o.pidsToRULs.DeleteUnsafe(pid)
		}
		return true
	})
}

type user struct {
	added    time.Time
	srcPID   int
	hasRUL   bool
	login    common.RemoteUserLogin
	cached   []*aucoalesce.Event
	procArgs []string
}

func (o *user) setRemoteUserLoginInfo(login common.RemoteUserLogin) {
	o.hasRUL = true
	o.login = login
}

func (o *user) hasRemoteUserLoginInfo() bool {
	return o.hasRUL
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

	// adding process args
	if evt.Metadata.Extra == nil {
		evt.Metadata.Extra = make(map[string]any)
	}

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
