package metrics

const (
	// MetricsNamespace is the namespace for all metrics. This name is
	// prepended to all metrics.
	MetricsNamespace = "audito_maldito"
)

// LoginType is the type of login.
type LoginType string

const (
	// SSHLogin is the login type for SSH logins.
	SSHCertLogin LoginType = "ssh-cert"
	// SSHKeyLogin is the login type for SSH key logins.
	SSHKeyLogin LoginType = "ssh-key"
	// SSHCertLogin is the login type for SSH certificate logins.
	PasswordLogin LoginType = "password"
	// PasswordLogin is the login type for password logins.
	UnknownLogin LoginType = "unknown"
)

type OutcomeType string

const (
	// Success is the outcome type for successful logins.
	Success OutcomeType = "success"
	// Failure is the outcome type for failed logins.
	Failure OutcomeType = "failure"
)

type ErrorType string

const (
	// ErrorTypeJournaldWait is the error type for errors waiting for journald.
	ErrorTypeJournaldWait ErrorType = "journald_wait"
)
