package auditd

import (
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusMetricsProvider struct {
	remoteLogins prometheus.Counter
}

func NewPrometheusMetricsProvider() *PrometheusMetricsProvider {
	return NewPrometheusMetricsProviderForRegisterer(prometheus.DefaultRegisterer)
}

func NewPrometheusMetricsProviderForRegisterer(r prometheus.Registerer) *PrometheusMetricsProvider {
	p := &PrometheusMetricsProvider{
		remoteLogins: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:      "remote_logins_total",
				Namespace: "audito_maldito",
				Help:      "The total number of remote logins.",
			},
		),
	}
	// This is variadic function so we can pass as many metrics as we want
	r.MustRegister(p.remoteLogins)
	return p
}

func (p *PrometheusMetricsProvider) IncLogins() {
	// TODO: Add labels .WithLabelValues
	p.remoteLogins.Inc()
}
