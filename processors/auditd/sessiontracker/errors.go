package sessiontracker

// SessionTrackerError is used to return errors pertaining to session audits
type SessionTrackerError struct {
	remoteLoginFail bool   // set when remote login cannot be validated
	parsePIDFail    bool   // set when PID of the session cannot be parsed
	auditWriteFail  bool   // set when the audit event fails to write to event writer
	message         string // the error message
	inner           error  // the error object
}

// RemoteLoginFailed returns true if the remote login validation has failed
func (o *SessionTrackerError) RemoteLoginFailed() bool {
	return o.remoteLoginFail
}

// ParsePIDFailed returns true if the PID of the session could not be parsed
func (o *SessionTrackerError) ParsePIDFailed() bool {
	return o.parsePIDFail
}

// AuditEventWriteFailed returns true when the audit event write fails
func (o *SessionTrackerError) AuditEventWriteFailed() bool {
	return o.auditWriteFail
}

// Error returns the error message
func (o *SessionTrackerError) Error() string {
	return o.message
}

// Unwrap unwraps the error content
func (o *SessionTrackerError) Unwrap() error {
	return o.inner
}
