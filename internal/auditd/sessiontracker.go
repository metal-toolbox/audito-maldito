package auditd

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

// newSessionTracker returns a new instance of a sessionTracker.
func newSessionTracker(eventWriter common.AuditEventWriter) *sessionTracker {
	return &sessionTracker{
		sessIDsToUsers: make(map[string]*user),
		pidsToRULs:     make(map[int]common.RemoteUserLogin),
		eventWriter:    eventWriter,
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
	eventWriter common.AuditEventWriter
}

func (o *sessionTracker) remoteLogin(rul common.RemoteUserLogin) error {
	var debugLogger *zap.SugaredLogger
	if logger.Level() == zap.DebugLevel {
		debugLogger = logger.With("RemoteUserLogin", rul)
		debugLogger.Debugln("new remote user login")
	}

	err := rul.Validate()
	if err != nil {
		return &sessionTrackerError{
			remoteLoginFail: true,
			message:         fmt.Sprintf("failed to validate remote user login - %s", err),
			inner:           err,
		}
	}

	// Check if there is an auditd session for this login.
	for asi, u := range o.sessIDsToUsers {
		if u.srcPID == rul.PID {
			if debugLogger != nil {
				debugLogger.With(
					"auditSessionID", asi,
					"auditSessionStartTime", u.added,
					"numCachedAuditEvents", len(u.cached),
					"hasRUL", u.hasRUL).
					Debugln("found existing audit session for remote user login")
			}

			u.hasRUL = true
			u.login = rul

			return u.writeAndClearCache(o.eventWriter)
		}
	}

	if debugLogger != nil {
		debugLogger.Debugln("no matching audit session found")
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

	var debugLogger *zap.SugaredLogger
	if logger.Level() == zap.DebugLevel {
		debugLogger = logger.With(
			"auditEvent", *event,
			"auditEventType", event.Type.String(),
			"auditSessionID", event.Session)
		debugLogger.Debugln("new audit event")
	}

	u, hasSession := o.sessIDsToUsers[event.Session]
	//nolint:nestif // Refactor later.
	if hasSession {
		// Either write the audit event to the event writer
		// or cache it for later.

		if debugLogger != nil {
			debugLogger.With(
				"auditSessionStartTime", u.added,
				"numCachedAuditEvents", len(u.cached),
				"hasRUL", u.hasRUL).
				Debugln("found existing audit session for audit event")
		}

		if u.hasRUL {
			// It looks like AUDIT_CRED_DISP indicates the
			// canonical end of a user session - but, there is
			// also AUDIT_USER_END, which occurs just before.
			if event.Type == auparse.AUDIT_CRED_DISP {
				defer delete(o.sessIDsToUsers, event.Session)
			}

			err := u.writeAndClearCache(o.eventWriter)
			if err != nil {
				return &sessionTrackerError{
					auditEventFail: true,
					message: fmt.Sprintf("failed to write cached events for user '%s' - %s",
						u.login.CredUserID, err),
					inner: err,
				}
			}

			err = o.eventWriter.Write(u.toAuditEvent(event))
			if err != nil {
				return &sessionTrackerError{
					auditEventFail: true,
					message:        err.Error(),
					inner:          err,
				}
			}

			return nil
		}
	} else {
		// Create a new audit session.

		if event.Type != auparse.AUDIT_LOGIN {
			if debugLogger != nil {
				debugLogger.Debugln("skipping creation of new audit session for audit event")
			}

			// It appears AUDIT_LOGIN indicates the
			// canonical start of a user session.
			// At least, it is the event type
			// associated with a user-specific
			// sshd process.
			return nil
		}

		if debugLogger != nil {
			debugLogger.Debugln("creating new audit session for audit event")
		}

		srcPID, err := strconv.Atoi(event.Process.PID)
		if err != nil {
			return &sessionTrackerError{
				auditEventFail: true,
				message: fmt.Sprintf("failed to parse audit session init event pid for session id '%s' ('%s') - %s",
					event.Session, event.Process.PID, err),
				inner: err,
			}
		}

		u = &user{
			added:  time.Now(),
			srcPID: srcPID,
		}

		if rul, hasRUL := o.pidsToRULs[srcPID]; hasRUL {
			if debugLogger != nil {
				debugLogger.Debugln("found existing remote user login for new audit session")
			}

			delete(o.pidsToRULs, srcPID)

			u.hasRUL = true
			u.login = rul

			o.sessIDsToUsers[event.Session] = u

			err = o.eventWriter.Write(u.toAuditEvent(event))
			if err != nil {
				return &sessionTrackerError{
					auditEventFail: true,
					message:        err.Error(),
					inner:          err,
				}
			}

			return nil
		}

		if debugLogger != nil {
			debugLogger.Debugln("no existing remote user login for new audit session")
		}
	}

	if debugLogger != nil {
		debugLogger.Debugln("caching audit event")
	}

	// Cache the event if the audit session does not have
	// any associated common.RemoteUserLogin object.
	u.cached = append(u.cached, event)
	o.sessIDsToUsers[event.Session] = u

	return nil
}

func (o *sessionTracker) deleteUsersWithoutLoginsBefore(t time.Time) {
	var debugLogger *zap.SugaredLogger
	if logger.Level() == zap.DebugLevel {
		debugLogger = logger.With(
			"cacheCleanup", "deleteUsersWithoutLoginsBefore",
			"before", t.String())
	}

	for id, u := range o.sessIDsToUsers {
		if !u.hasRUL && u.added.Before(t) {
			if debugLogger != nil {
				debugLogger.With(
					"auditSessionID", id,
					"auditSessionStartTime", u.added.String()).
					Debugln("removing unused audit session")
			}

			delete(o.sessIDsToUsers, id)
		}
	}
}

func (o *sessionTracker) deleteRemoteUserLoginsBefore(t time.Time) {
	var debugLogger *zap.SugaredLogger
	if logger.Level() == zap.DebugLevel {
		debugLogger = logger.With(
			"cacheCleanup", "deleteRemoteUserLoginsBefore",
			"before", t.String())
	}

	for pid, userLogin := range o.pidsToRULs {
		if userLogin.Source.LoggedAt.Before(t) {
			if debugLogger != nil {
				debugLogger.With(
					"pid", pid,
					"source", *userLogin.Source).
					Debugln("removing unused remote user login")
			}

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

func (o *user) writeAndClearCache(writer common.AuditEventWriter) error {
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
