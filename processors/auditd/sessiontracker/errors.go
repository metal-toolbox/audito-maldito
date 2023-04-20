package sessiontracker

type SessionTrackerError struct {
	remoteLoginFail bool
	auditEventFail  bool
	message         string
	inner           error
}

func (o *SessionTrackerError) RemoteLoginFailed() bool {
	return o.remoteLoginFail
}

func (o *SessionTrackerError) AuditEventFailed() bool {
	return o.auditEventFail
}

func (o *SessionTrackerError) Error() string {
	return o.message
}

func (o *SessionTrackerError) Unwrap() error {
	return o.inner
}
