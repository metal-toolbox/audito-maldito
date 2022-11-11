package common

import "github.com/metal-toolbox/auditevent"

type RemoteUserLogin struct {
	Source *auditevent.AuditEvent
	// TODO: Talk to Ozz about parsing this to an int earlier in the code.
	PID        string
	CredUserID string
}
