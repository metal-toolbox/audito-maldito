package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/zapr"
	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/ingesters/journald"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/internal/util"
	"github.com/metal-toolbox/audito-maldito/processors/auditd"
	"github.com/metal-toolbox/audito-maldito/processors/auditd/dirreader"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

func RunJournald(ctx context.Context, osArgs []string, h *health.Health, optLoggerConfig *zap.Config) error {
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
	sshd.SetLogger(logger)

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

	logger.Infoln("starting workers...")

	handleMetricsAndHealth(groupCtx, appCfg.metricsConfig, eg, h)

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
		logger.Infof("linux audit log dir reader worker exited (%v)", err)
		return err
	})

	lastReadJournalTS := lastReadJournalTimeStamp()
	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)
	pprov := metrics.NewPrometheusMetricsProvider()

	handleAuditLogMetrics(
		groupCtx,
		eg,
		pprov,
		appCfg.metricsConfig.auditMetricsSecondsInterval,
		appCfg.metricsConfig.auditLogWriteTimeSecondThreshold,
		appCfg.metricsConfig.enableAuditMetrics,
	)
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
		logger.Infof("linux audit worker exited (%v)", err)
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
