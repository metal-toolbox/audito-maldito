package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/auditevent/helpers"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

func mainWithErr() error {
	var bootID string
	var auditlogpath string

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flag.StringVar(&bootID, "boot-id", "", "Boot-ID to read from the journal")
	flag.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eg, gctx := errgroup.WithContext(ctx)

	distro, err := util.Distro()
	if err != nil {
		return fmt.Errorf("fatal: failed to get os distro type: %w", err)
	}

	mid, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("fatal: failed to get machine id: %w", miderr)
	}

	nodename, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("fatal: failed to get node name: %w", nodenameerr)
	}

	if err := common.EnsureFlushDirectory(); err != nil {
		return fmt.Errorf("fatal: failed to ensure flush directory: %w", err)
	}

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(ctx, auditlogpath)
	if auditfileerr != nil {
		return fmt.Errorf("fatal: failed to open audit log file: %w", auditfileerr)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		return err
	}

	defer func() {
		_ = logger.Sync() //nolint
	}()

	sugar := logger.Sugar()
	journald.Logger = sugar

	sugar.Infoln("starting workers...")

	eg.Go(func() error {
		jp := journald.Processor{
			BootID:    bootID,
			MachineID: mid,
			NodeName:  nodename,
			Distro:    distro,
			EventW:    auditevent.NewDefaultAuditEventWriter(auf),
		}
		return jp.Read(gctx)
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("fatal: error while waiting for workers: %w", err)
	}

	sugar.Infoln("all workers finished")

	return err
}

func main() {
	err := mainWithErr()
	if err != nil {
		log.Fatalln(err)
	}
}
