// package metrics is a common package for audito maldito's metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetricsProvider is a metrics provider that uses Prometheus.
type PrometheusMetricsProvider struct {
	auditLogCheck      *prometheus.GaugeVec
	auditLogModifyTime *prometheus.GaugeVec
	errors             *prometheus.CounterVec
	remoteLogins       *prometheus.CounterVec
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
		auditLogCheck: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "audit_log_check",
				Namespace: MetricsNamespace,
				Help:      "Checks audit.log is being written to. 0 for negative, 1 for positive",
			},
			[]string{"threshold_time_in_seconds"},
		),
		auditLogModifyTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "audit_log_modify_time",
				Namespace: MetricsNamespace,
				Help:      "Sets audit.log last modify time",
			},
			[]string{},
		),

		errors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "errors_total",
				Namespace: MetricsNamespace,
				Help:      "The total number of errors.",
			},
			[]string{"type"},
		),
		remoteLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:      "remote_logins_total",
				Namespace: MetricsNamespace,
				Help:      "The total number of remote logins.",
			},
			[]string{"method", "outcome"},
		),
	}

	// This is variadic function so we can pass as many metrics as we want
	r.MustRegister(p.remoteLogins, p.auditLogCheck, p.auditLogModifyTime)
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

// SetAuditCheck sets status of audit.log writes. 0 for negative, 1 for positive.
func (p *PrometheusMetricsProvider) SetAuditLogCheck(result float64, threshold string) {
	p.auditLogCheck.WithLabelValues(threshold).Set(result)
}

// SetAuditLogModifyTime sets last modify time in seconds.
func (p *PrometheusMetricsProvider) SetAuditLogModifyTime(result float64) {
	p.auditLogModifyTime.WithLabelValues().Set(result)
}
