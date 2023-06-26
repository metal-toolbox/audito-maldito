package cmd

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
)

const usage = `audito-maldito

DESCRIPTION
  audito-maldito is a daemon that monitors OpenSSH server logins and
  produces structured audit events describing what authenticated users
  did while logged in (e.g., what programs they executed).

OPTIONS
`

var logger *zap.SugaredLogger

const (
	// DefaultHTTPServerReadTimeout is the default HTTP server read timeout.
	DefaultHTTPServerReadTimeout = 1 * time.Second
	// DefaultHTTPServerReadHeaderTimeout is the default HTTP server read header timeout.
	DefaultHTTPServerReadHeaderTimeout = 5 * time.Second
	// DefaultAuditCheckInterval when to check audit.log modify time.
	DefaultAuditCheckInterval = 15 * time.Second
	// DefaultAuditModifyTimeThreshold seconds since last write to audit.log before alerting.
	DefaultAuditModifyTimeThreshold = 86400
)

type metricsConfig struct {
	enableMetrics                    bool
	enableHealthz                    bool
	enableAuditMetrics               bool
	httpServerReadTimeout            time.Duration
	httpServerReadHeaderTimeout      time.Duration
	auditMetricsSecondsInterval      time.Duration
	auditLogWriteTimeSecondThreshold int
}

// handleMetricsAndHealth starts a HTTP server on port 2112 to serve metrics
// and health endpoints.
//
// If metrics are disabled, the /metrics endpoint will return 404.
// If health is disabled, the /readyz endpoint will return 404.
// If both are disabled, the HTTP server will not be started.
func handleMetricsAndHealth(ctx context.Context, mc metricsConfig, eg *errgroup.Group, h *health.Health) {
	server := &http.Server{
		Addr:              ":2112",
		ReadTimeout:       mc.httpServerReadTimeout,
		ReadHeaderTimeout: mc.httpServerReadHeaderTimeout,
	}

	if mc.enableMetrics {
		http.Handle("/metrics", promhttp.Handler())
	}

	if mc.enableHealthz {
		http.Handle("/readyz", h.ReadyzHandler())
		// TODO: Add livez endpoint
	}

	if mc.enableMetrics || mc.enableHealthz {
		eg.Go(func() error {
			logger.Infof("starting HTTP server on address '%s'...", server.Addr)
			if err := server.ListenAndServe(); err != nil {
				return err
			}
			return nil
		})

		eg.Go(func() error {
			<-ctx.Done()
			logger.Infoln("stopping HTTP server...")
			return server.Shutdown(ctx)
		})
	}
}

func handleAuditLogMetrics(
	ctx context.Context,
	mc metricsConfig,
	eg *errgroup.Group,
	pprov *metrics.PrometheusMetricsProvider,
) {
	if !mc.enableAuditMetrics {
		return
	}

	auditLogFilePath := "/var/log/audit/audit.log"

	eg.Go(func() error {
		ticker := time.NewTicker(mc.auditMetricsSecondsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s, err := os.Stat(auditLogFilePath)
				if err != nil {
					logger.Errorf("error stat-ing %s", auditLogFilePath)
					continue
				}

				if time.Since(s.ModTime()).Seconds() > float64(mc.auditLogWriteTimeSecondThreshold) {
					pprov.SetAuditLogCheck(0, strconv.Itoa(mc.auditLogWriteTimeSecondThreshold))
				} else {
					pprov.SetAuditLogCheck(1, strconv.Itoa(mc.auditLogWriteTimeSecondThreshold))
				}

				pprov.SetAuditLogModifyTime(float64(s.ModTime().Unix()))
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}
