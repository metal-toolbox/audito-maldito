package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/internal/auditd"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

var logger *zap.SugaredLogger

func mainWithErr() error {
	var bootID string
	var auditlogpath string
	var auditLogDirPath string

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flag.StringVar(&bootID, "boot-id", "", "Boot-ID to read from the journal")
	flag.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flag.StringVar(&auditLogDirPath, "audit-dir-path", "/var/log/audit", "Path to the Linux audit log directory")

	flag.Parse()

	l, err := zap.NewProduction()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)
	journald.SetLogger(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eg, gctx := errgroup.WithContext(ctx)

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

	// TODO: Figure out cancellation method that won't result in deadlock
	// when waiting for underlying files to be closed.
	dr, err := auditd.DirReaderFor(ctx, auditLogDirPath)
	if err != nil {
		return fmt.Errorf("failed to create audit dir reader for '%s' - %w",
			auditLogDirPath, err)
	}

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(ctx, auditlogpath)
	if auditfileerr != nil {
		return fmt.Errorf("failed to open audit log file: %w", auditfileerr)
	}

	var afterUsec uint64

	lastRead, err := common.GetLastRead()
	switch {
	case err != nil:
		afterUsec = uint64(time.Now().UnixMicro())

		logger.Warnf("failed to read last read timestamp for journal - "+
			"reading from current time (reason: '%s')", err.Error())
	case lastRead == 0:
		afterUsec = uint64(time.Now().UnixMicro())

		logger.Info("last read timestamp for journal is zero - " +
			"reading from current time")
	default:
		afterUsec = lastRead

		logger.Infof("last read timestamp for journal is: '%d'", lastRead)
	}

	logger.Infoln("starting workers...")

	eventWriter := auditevent.NewDefaultAuditEventWriter(auf)
	logins := make(chan common.RemoteUserLogin)

	eg.Go(func() error {
		jp := journald.Processor{
			BootID:    bootID,
			MachineID: mid,
			NodeName:  nodename,
			Distro:    distro,
			EventW:    eventWriter,
			Logins:    logins,
			CurrentTS: afterUsec,
		}
		return jp.Read(gctx)
	})

	eg.Go(func() error {
		ap := auditd.Auditd{
			After:  time.UnixMicro(int64(afterUsec)),
			Source: dr,
			Logins: logins,
			EventW: eventWriter,
		}
		return ap.Read(gctx)
	})

	// TODO: What happens if one routine exits, but the rest keep going?
	if err := eg.Wait(); err != nil {
		if !errors.Is(err, context.Canceled) {
			return fmt.Errorf("workers finished with error: %w", err)
		}
	}

	logger.Infoln("all workers finished without error")

	return nil
}

func main() {
	err := mainWithErr()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}
