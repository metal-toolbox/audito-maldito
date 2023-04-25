package sessiontracker

type SessionTrackerError struct {
	remoteLoginFail bool
	parsePIDFail    bool
	auditWriteFail  bool
	message         string
	inner           error
}

func (o *SessionTrackerError) RemoteLoginFailed() bool {
	return o.remoteLoginFail
}

func (o *SessionTrackerError) ParsePIDFailed() bool {
	return o.parsePIDFail
}

func (o *SessionTrackerError) AuditEventWriteFailed() bool {
	return o.auditWriteFail
}

func (o *SessionTrackerError) Error() string {
	return o.message
}

func (o *SessionTrackerError) Unwrap() error {
	return o.inner
}
