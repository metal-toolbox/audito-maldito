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

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald/consumer"
	"github.com/metal-toolbox/audito-maldito/internal/journald/producer"
	"github.com/metal-toolbox/audito-maldito/internal/journald/types"
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

	distro, err := util.Distro()
	if err != nil {
		return fmt.Errorf("fatal: failed to get os distro type: %w", err)
	}

	if err := common.EnsureFlushDirectory(); err != nil {
		return fmt.Errorf("fatal: failed to ensure flush directory: %w", err)
	}

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(ctx, auditlogpath)
	if auditfileerr != nil {
		return fmt.Errorf("fatal: failed to open audit log file: %w", auditfileerr)
	}

	log.Println("Starting workers...")
	numWorkers := 2

	journaldEntries := make(chan *types.LogEntry)
	routineExits := make(chan error, numWorkers)

	go producer.JournaldProducer(ctx, producer.Config{
		Entries: journaldEntries,
		BootID:  bootID,
		Distro:  distro,
		Exited:  routineExits,
	})

	go consumer.JournaldConsumer(ctx, consumer.Config{
		Entries: journaldEntries,
		EventW:  auditevent.NewDefaultAuditEventWriter(auf),
		Exited:  routineExits,
	})

	// Wait until one of the Go routines exits.
	err = <-routineExits

	log.Println("Waiting for remaining worker(s) to exit...")

	// Mark context as "done", thus triggering the second routine to exit.
	// After marking context as done, wait for second routine to exit.
	stop()
	<-routineExits

	log.Println("All workers finished")

	return err
}

func main() {
	err := mainWithErr()
	if err != nil {
		log.Fatalln(err)
	}
}
