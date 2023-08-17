package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/auditlog"
	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/ingesters/rocky"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

func RunNamedPipe(ctx context.Context, osArgs []string, h *health.Health, optLoggerConfig *zap.Config) error {
	var appEventsOutput string
	var auditdLogFilePath string
	var sshdLogFilePath string
	var metricsConfig metricsConfig

	logLevel := zapcore.InfoLevel

	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	flagSet.Var(&logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.BoolVar(&metricsConfig.enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	flagSet.BoolVar(&metricsConfig.enableHealthz, "healthz", false, "Enable HTTP health endpoints server")
	flagSet.BoolVar(&metricsConfig.enableAuditMetrics, "audit-metrics", false, "Enable Prometheus audit metrics")

	flagSet.DurationVar(&metricsConfig.httpServerReadTimeout, "http-server-read-timeout",
		DefaultHTTPServerReadTimeout, "HTTP server read timeout")
	flagSet.DurationVar(&metricsConfig.httpServerReadHeaderTimeout, "http-server-read-header-timeout",
		DefaultHTTPServerReadHeaderTimeout, "HTTP server read header timeout")
	flagSet.DurationVar(
		&metricsConfig.auditMetricsSecondsInterval,
		"audit-seconds-interval",
		DefaultAuditCheckInterval,
		"Interval in seconds to collect audit metrics")
	flagSet.IntVar(
		&metricsConfig.auditLogWriteTimeSecondThreshold,
		"audit-log-last-modify-seconds-threshold",
		DefaultAuditModifyTimeThreshold,
		"seconds since last write to audit.log before alerting")

	flagSet.StringVar(
		&appEventsOutput,
		"app-events-output",
		"/app-audit/app-events-output.log",
		"Path to the app events output")
	flagSet.StringVar(
		&sshdLogFilePath,
		"sshd-pipe-path",
		"/app-audit/sshd-pipe",
		"Path to the sshd log named pipe file")
	flagSet.StringVar(
		&auditdLogFilePath,
		"auditd-pipe-path",
		"/app-audit/audit-pipe",
		"Path to the audit log named pipe file")

	flagSet.Usage = func() {
		os.Stderr.WriteString(usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	err := flagSet.Parse(osArgs[1:])
	if err != nil {
		return err
	}

	if optLoggerConfig == nil {
		cfg := zap.NewProductionConfig()
		optLoggerConfig = &cfg
	}

	optLoggerConfig.Level = zap.NewAtomicLevelAt(logLevel)

	l, err := optLoggerConfig.Build()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)
	sshd.SetLogger(logger)

	distro, err := util.Distro()
	if err != nil {
		err := fmt.Errorf("failed to get os distro type: %w", err)
		logger.Errorf(err.Error())
		return err
	}

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("failed to get machine id: %w", miderr)
	}

	nodeName, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("failed to get node name: %w", nodenameerr)
	}

	eg, groupCtx := errgroup.WithContext(ctx)

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(groupCtx, appEventsOutput, zapr.NewLogger(l))
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)
	pprov := metrics.NewPrometheusMetricsProvider()

	logger.Infoln("starting workers...")
	handleMetricsAndHealth(groupCtx, metricsConfig, eg, h)
	handleAuditLogMetrics(groupCtx, metricsConfig, eg, pprov)

	h.AddReadiness(namedpipe.NamedPipeProcessorComponentName)
	eg.Go(func() error {
		err := common.IsNamedPipe(sshdLogFilePath)
		if err != nil {
			return fmt.Errorf("failed to check if sshd log path is a named pipe: %q - %w",
				sshdLogFilePath, err)
		}

		sshdProcessor := sshd.NewSshdProcessor(groupCtx, logins, nodeName, mid, eventWriter, pprov)
		npi := namedpipe.NewNamedPipeIngester(logger, h)
		if distro == util.DistroRocky {
			rp := rocky.NewRockyIngester(sshdLogFilePath, sshdProcessor, npi)
			err = rp.Ingest(groupCtx)
		} else {
			sli := syslog.NewSyslogIngester(sshdLogFilePath, sshdProcessor, npi)

			err = sli.Ingest(groupCtx)
		}

		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("syslog ingester exited (%v)", err)
		}
		return err
	})

	auditLogChanBufSize := 10000
	auditLogChan := make(chan string, auditLogChanBufSize)

	h.AddReadiness(namedpipe.NamedPipeProcessorComponentName)
	eg.Go(func() error {
		err := common.IsNamedPipe(auditdLogFilePath)
		if err != nil {
			return fmt.Errorf("failed to check if auditd log path is a named pipe: %q - %w",
				auditdLogFilePath, err)
		}

		np := namedpipe.NewNamedPipeIngester(logger, h)
		alp := auditlog.NewAuditLogIngester(auditdLogFilePath, auditLogChan, np)

		err = alp.Ingest(groupCtx)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit log ingester exited (%v)", err)
		}
		return err
	})

	h.AddReadiness(auditd.AuditdProcessorComponentName)
	eg.Go(func() error {
		ap := auditd.Auditd{
			Audits: auditLogChan,
			Logins: logins,
			EventW: eventWriter,
			Health: h,
		}

		err := ap.Read(groupCtx)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit worker exited (%v)", err)
		}
		return err
	})

	if err := eg.Wait(); err != nil {
		// We cannot treat errors containing context.Canceled
		// as non-errors because the errgroup.Group uses its
		// own context, which is canceled if one of the Go
		// routines returns a non-nil error. Thus, treating
		// context.Canceled as a graceful shutdown may hide

		// an error returned by one of the Go routines.
		return err
	}

	logger.Infoln("all workers finished without error")

	return nil
}
