package common

import "github.com/metal-toolbox/auditevent"

type RemoteUserLogin struct {
	Source     *auditevent.AuditEvent
	PID        int
	CredUserID string
}

func (o RemoteUserLogin) Validate() error {
	if o.Source == nil {
		return &remoteUserLoginValidateError{
			noEvent: true,
			message: "audit event is nil",
		}
	}

	if o.PID == 0 {
		return &remoteUserLoginValidateError{
			noPID:   true,
			message: "pid is zero",
		}
	}

	if o.CredUserID == "" {
		return &remoteUserLoginValidateError{
			noCred:  true,
			message: "user id is empty",
		}
	}

	return nil
}
