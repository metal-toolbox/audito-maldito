package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
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

	w := auditevent.NewDefaultAuditEventWriter(auf)

	journaldChan := make(chan *types.LogEntry)
	log.Println("Starting workers")

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go producer.JournaldProducer(ctx, producer.JournaldProducerConfig{
		WG:      wg,
		Entries: journaldChan,
		BootID:  bootID,
		Distro:  distro,
	})

	wg.Add(1)
	go consumer.JournaldConsumer(ctx, wg, journaldChan, w)

	wg.Wait()

	log.Println("All workers finished")

	return nil
}

func main() {
	err := mainWithErr()
	if err != nil {
		log.Fatalln(err)
	}
}
