// package metrics is a common package for audito maldito's metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
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

// PrometheusMetricsProvider is a metrics provider that uses Prometheus.
type PrometheusMetricsProvider struct {
	remoteLogins *prometheus.CounterVec
}

// NewPrometheusMetricsProvider returns a new PrometheusMetricsProvider.
func NewPrometheusMetricsProvider() *PrometheusMetricsProvider {
	return NewPrometheusMetricsProviderForRegisterer(prometheus.DefaultRegisterer)
}

// NewPrometheusMetricsProviderForRegisterer returns a new PrometheusMetricsProvider
// that uses the given prometheus.Registerer.
func NewPrometheusMetricsProviderForRegisterer(r prometheus.Registerer) *PrometheusMetricsProvider {
	p := &PrometheusMetricsProvider{
		remoteLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "remote_logins_total",
				Namespace: "audito_maldito",
				Help:      "The total number of remote logins.",
			},
			[]string{"method", "outcome"},
		),
	}

	// This is variadic function so we can pass as many metrics as we want
	r.MustRegister(p.remoteLogins)
	return p
}

// IncLogins increments the number of logins by the given type.
func (p *PrometheusMetricsProvider) IncLogins(loginType LoginType, outcome OutcomeType) {
	p.remoteLogins.WithLabelValues(string(loginType), string(outcome)).Inc()
}
