package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/auditlog"
	"github.com/metal-toolbox/audito-maldito/ingesters/rocky"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/metrics"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

const usage = `audito-maldito

DESCRIPTION
  audito-maldito is a daemon that monitors OpenSSH server logins and
  produces structured audit events describing what authenticated users
  did while logged in (e.g., what programs they executed).

OPTIONS
`

var logger *zap.SugaredLogger

func Run(ctx context.Context, osArgs []string, h *common.Health, optLoggerConfig *zap.Config) error {
	var bootID string
	var appEventsOutput string
	var auditdLogFilePath string
	var sshdLogFilePath string
	var enableMetrics bool

	logLevel := zapcore.DebugLevel // TODO: Switch default back to zapcore.ErrorLevel.

	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.Var(&logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	flagSet.StringVar(
		&appEventsOutput,
		"app-events-output",
		"/app-audit/app-events-output.log",
		"Path to the app events output")
	flagSet.StringVar(
		&sshdLogFilePath,
		"sshd-log-file-path",
		"/var/log/audito-maldito/sshd-pipe",
		"Path to the sshd log file")
	flagSet.StringVar(
		&auditdLogFilePath,
		"auditd-log-file-path",
		"/var/log/audito-maldito/audit-pipe",
		"Path to the audit log file")

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

	if enableMetrics {
		server := &http.Server{Addr: ":2112"} //nolint
		eg.Go(func() error {
			http.Handle("/metrics", promhttp.Handler())
			logger.Infoln("Starting HTTP metrics server on :2112")
			if err := server.ListenAndServe(); err != nil {
				logger.Errorf("Failed to start HTTP metrics server: %v", err)
				return err
			}
			return nil
		})
		eg.Go(func() error {
			<-groupCtx.Done()
			logger.Infoln("Stopping HTTP metrics server")
			return server.Shutdown(groupCtx)
		})
	}

	logger.Infoln("starting workers...")

	h.AddReadiness()
	eg.Go(func() error {
		sshdProcessor := sshd.NewSshdProcessor(groupCtx, logins, nodeName, mid, eventWriter, pprov)

		if distro == util.DistroRocky {
			rp := rocky.RockyProcessor{FilePath: sshdLogFilePath, SshdProcessor: *sshdProcessor, Logger: logger, Health: h}
			err = rp.Ingest(groupCtx)
		} else {
			jdp := syslog.SyslogIngester{FilePath: sshdLogFilePath, SshdProcessor: *sshdProcessor, Logger: logger, Health: h}
			err = jdp.Ingest(groupCtx)
		}

		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("syslog ingester exited (%v)", err)
		}
		return err
	})

	auditLogChanBufSize := 10000
	auditLogChan := make(chan string, auditLogChanBufSize)

	h.AddReadiness()
	eg.Go(func() error {
		alp := auditlog.AuditLogIngester{
			FilePath:     auditdLogFilePath,
			AuditLogChan: auditLogChan,
			Logger:       logger,
			Health:       h,
		}

		err := alp.Ingest(groupCtx)
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("audit log ingester exited (%v)", err)
		}
		return err
	})

	h.AddReadiness()
	eg.Go(func() error {
		ap := auditd.Auditd{
			Audits: auditLogChan,
			Logins: logins,
			EventW: eventWriter,
			Health: h,
		}

		err := ap.Process(groupCtx)
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
