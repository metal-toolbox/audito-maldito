package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/journald"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/auditd/dirreader"
	"github.com/metal-toolbox/audito-maldito/processors/varlogsecure"
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
)

type appConfig struct {
	bootID                      string
	auditlogpath                string
	auditLogDirPath             string
	enableMetrics               bool
	enableHealthz               bool
	httpServerReadTimeout       time.Duration
	httpServerReadHeaderTimeout time.Duration
	logLevel                    zapcore.Level
}

func parseFlags(osArgs []string) (*appConfig, error) {
	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	appConfig := &appConfig{
		logLevel: zapcore.InfoLevel,
	}

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&appConfig.bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.StringVar(&appConfig.auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flagSet.StringVar(&appConfig.auditLogDirPath, "audit-dir-path", "/var/log/audit",
		"Path to the Linux audit log directory")
	flagSet.Var(&appConfig.logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.BoolVar(&appConfig.enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	flagSet.BoolVar(&appConfig.enableHealthz, "healthz", false, "Enable HTTP health endpoints server")
	flagSet.DurationVar(&appConfig.httpServerReadTimeout, "http-server-read-timeout",
		DefaultHTTPServerReadTimeout, "HTTP server read timeout")
	flagSet.DurationVar(&appConfig.httpServerReadHeaderTimeout, "http-server-read-header-timeout",
		DefaultHTTPServerReadHeaderTimeout, "HTTP server read header timeout")

	flagSet.Usage = func() {
		os.Stderr.WriteString(usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if err := flagSet.Parse(osArgs[1:]); err != nil {
		return nil, err
	}

	return appConfig, nil
}

func Run(ctx context.Context, osArgs []string, h *health.Health, optLoggerConfig *zap.Config) error {
	appCfg, err := parseFlags(osArgs)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if optLoggerConfig == nil {
		cfg := zap.NewProductionConfig()
		optLoggerConfig = &cfg
	}

	optLoggerConfig.Level = zap.NewAtomicLevelAt(appCfg.logLevel)

	l, err := optLoggerConfig.Build()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)
	journald.SetLogger(logger)
	processors.SetLogger(logger)

	distro, err := util.Distro()
	if err != nil {
		return fmt.Errorf("failed to get os distro type: %w", err)
	}

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("failed to get machine id: %w", miderr)
	}

	nodename, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("failed to get node name: %w", nodenameerr)
	}

	if err := common.EnsureFlushDirectory(); err != nil {
		return fmt.Errorf("failed to ensure flush directory: %w", err)
	}

	eg, groupCtx := errgroup.WithContext(ctx)

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(
		groupCtx, appCfg.auditlogpath, zapr.NewLogger(l))
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	handleMetricsAndHealth(groupCtx, appCfg, eg, h)

	logDirReader, err := dirreader.StartLogDirReader(groupCtx, appCfg.auditLogDirPath)
	if err != nil {
		return fmt.Errorf("failed to create linux audit dir reader for '%s' - %w",
			appCfg.auditLogDirPath, err)
	}

	h.AddReadiness(dirreader.DirReaderComponentName)
	go func() {
		<-logDirReader.InitFilesDone()
		h.OnReady(dirreader.DirReaderComponentName)
	}()

	eg.Go(func() error {
		err := logDirReader.Wait()
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debugf("linux audit log dir reader worker exited (%v)", err)
		}
		return err
	})

	lastReadJournalTS := lastReadJournalTimeStamp()
	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)

	logger.Infoln("starting workers...")
	pprov := metrics.NewPrometheusMetricsProvider()

	runProcessorsForSSHLogins(groupCtx, logins, eg, distro,
		mid, nodename, appCfg.bootID, lastReadJournalTS, eventWriter, h, pprov)

	h.AddReadiness(auditd.AuditdProcessorComponentName)
	eg.Go(func() error {
		ap := auditd.Auditd{
			After:  time.UnixMicro(int64(lastReadJournalTS)),
			Audits: logDirReader.Lines(),
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
		return fmt.Errorf("workers finished with error: %w", err)
	}

	logger.Infoln("all workers finished without error")

	return nil
}

func runProcessorsForSSHLogins(
	ctx context.Context,
	logins chan<- common.RemoteUserLogin,
	eg *errgroup.Group,
	distro util.DistroType,
	mid string,
	nodename string,
	bootID string,
	lastReadJournalTS uint64,
	eventWriter *auditevent.EventWriter,
	h *health.Health,
	pprov *metrics.PrometheusMetricsProvider,
) {
	//nolint:exhaustive // In this case it's actually simpler to just default to journald
	switch distro {
	case util.DistroRocky:
		// TODO: handle last read timestamp
		eg.Go(func() error {
			h.AddReadiness(varlogsecure.VarLogSecureComponentName)
			vls := varlogsecure.VarLogSecure{
				L:         logger,
				Logins:    logins,
				NodeName:  nodename,
				MachineID: mid,
				AuWriter:  eventWriter,
				Health:    h,
				Metrics:   pprov,
			}
			if err := vls.Read(ctx); err != nil {
				logger.Errorf("varlogsecure worker failed: %v", err)
				return err
			}

			logger.Debugf("varlogsecure worker exited")
			return nil
		})
	default:
		h.AddReadiness(journald.JournaldReaderComponentName)
		eg.Go(func() error {
			jp := journald.Processor{
				BootID:    bootID,
				MachineID: mid,
				NodeName:  nodename,
				Distro:    distro,
				EventW:    eventWriter,
				Logins:    logins,
				CurrentTS: lastReadJournalTS,
				Health:    h,
				Metrics:   pprov,
			}

			err := jp.Read(ctx)
			if logger.Level().Enabled(zap.DebugLevel) {
				logger.Debugf("journald worker exited (%v)", err)
			}
			return err
		})
	}
}

// handleMetricsAndHealth starts a HTTP server on port 2112 to serve metrics and health endpoints.
// If metrics are disabled, the /metrics endpoint will return 404.
// If health is disabled, the /readyz endpoint will return 404.
// If both are disabled, the HTTP server will not be started.
func handleMetricsAndHealth(ctx context.Context, appCfg *appConfig, eg *errgroup.Group, h *health.Health) {
	server := &http.Server{
		Addr:              ":2112",
		ReadTimeout:       appCfg.httpServerReadTimeout,
		ReadHeaderTimeout: appCfg.httpServerReadHeaderTimeout,
	}

	if appCfg.enableMetrics {
		http.Handle("/metrics", promhttp.Handler())
	}

	if appCfg.enableHealthz {
		http.Handle("/readyz", h.ReadyzHandler())
		// TODO: Add livez endpoint
	}

	if appCfg.enableMetrics || appCfg.enableHealthz {
		eg.Go(func() error {
			logger.Infoln("Starting HTTP server on :2112")
			if err := server.ListenAndServe(); err != nil {
				logger.Errorf("Failed to start HTTP metrics server: %v", err)
				return err
			}
			return nil
		})

		eg.Go(func() error {
			<-ctx.Done()
			logger.Infoln("Stopping HTTP metrics server")
			return server.Shutdown(ctx)
		})
	}
}

// lastReadJournalTimeStamp returns the last-read journal entry's timestamp
// or a sensible default if the timestamp cannot be loaded.
func lastReadJournalTimeStamp() uint64 {
	lastRead, err := common.GetLastRead()
	switch {
	case err != nil:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Warnf("failed to read last read timestamp for journal - "+
			"reading from current time (reason: '%s')", err.Error())
	case lastRead == 0:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Info("last read timestamp for journal is zero - " +
			"reading from current time")
	default:
		logger.Infof("last read timestamp for journal is: '%d'", lastRead)
	}

	return lastRead
}
