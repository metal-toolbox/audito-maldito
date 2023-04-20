package app

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

	"github.com/metal-toolbox/audito-maldito/internal/auditd"
	"github.com/metal-toolbox/audito-maldito/internal/auditd/dirreader"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/journald"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/processors"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/internal/varlogsecure"
)

const usage = `audito-maldito

DESCRIPTION
  audito-maldito is a daemon that monitors OpenSSH server logins and
  produces structured audit events describing what authenticated users
  did while logged in (e.g., what programs they executed).

OPTIONS
`

var logger *zap.SugaredLogger

//nolint
func Run(ctx context.Context, osArgs []string, h *health.Health, optLoggerConfig *zap.Config) error {
	var bootID string
	var auditlogpath string
	var auditLogDirPath string
	var enableMetrics bool
	var enableHealthz bool
	logLevel := zapcore.ErrorLevel

	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flagSet.StringVar(&auditLogDirPath, "audit-dir-path", "/var/log/audit", "Path to the Linux audit log directory")
	flagSet.Var(&logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus HTTP /metrics server")
	flagSet.BoolVar(&enableHealthz, "healthz", false, "Enable HTTP health endpoints server")
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

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(groupCtx, auditlogpath, zapr.NewLogger(l))
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	server := &http.Server{Addr: ":2112"}

	if enableMetrics {
		http.Handle("/metrics", promhttp.Handler())
	}

	if enableHealthz {
		http.Handle("/readyz", h.ReadyzHandler())
		// TODO: Add livez endpoint
	}

	if enableMetrics || enableHealthz {
		eg.Go(func() error {
			logger.Infoln("Starting HTTP server on :2112")
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

	logDirReader, err := dirreader.StartLogDirReader(groupCtx, auditLogDirPath)
	if err != nil {
		return fmt.Errorf("failed to create linux audit dir reader for '%s' - %w",
			auditLogDirPath, err)
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
		mid, nodename, bootID, lastReadJournalTS, eventWriter, h, pprov)

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
