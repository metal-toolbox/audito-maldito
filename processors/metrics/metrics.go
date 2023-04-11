// package metrics is a common package for audito maldito's metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetricsProvider is a metrics provider that uses Prometheus.
type PrometheusMetricsProvider struct {
	remoteLogins *prometheus.CounterVec
	errors       *prometheus.CounterVec
}

// NewPrometheusMetricsProvider returns a new PrometheusMetricsProvider.
func NewPrometheusMetricsProvider() *PrometheusMetricsProvider {
	return NewPrometheusMetricsProviderForRegisterer(prometheus.DefaultRegisterer)
}

// NewPrometheusMetricsProviderForRegisterer returns a new PrometheusMetricsProvider
// that uses the given prometheus.Registerer.
// The following metrics are registered:
// - remote_logins_total (counter) - The total number of remote logins.
//   - Labels: method, outcome
//   - For more information about the labels, see the `LoginType` and `OutcomeType`
//
// - errors_total (counter) - The total number of errors.
//   - Labels: type
//   - For more information about the labels, see the `ErrorType`
func NewPrometheusMetricsProviderForRegisterer(r prometheus.Registerer) *PrometheusMetricsProvider {
	p := &PrometheusMetricsProvider{
		remoteLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "remote_logins_total",
				Namespace: MetricsNamespace,
				Help:      "The total number of remote logins.",
			},
			[]string{"method", "outcome"},
		),
		errors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "errors_total",
				Namespace: MetricsNamespace,
				Help:      "The total number of errors.",
			},
			[]string{"type"},
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

// IncErrors increments the number of errors by the given type.
func (p *PrometheusMetricsProvider) IncErrors(errorType ErrorType) {
	p.errors.WithLabelValues(string(errorType)).Inc()
}
