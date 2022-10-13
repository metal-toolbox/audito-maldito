package main

import (
	"context"
	"flag"
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
)

const (
	journalEntryBufferSize = 1000
)

func mainWithExitCode() int {
	var bootID string
	var auditlogpath string
	var wg sync.WaitGroup

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flag.StringVar(&bootID, "boot-id", "", "Boot-ID to read from the journal")
	flag.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := common.EnsureFlushDirectory(); err != nil {
		log.Printf("Error: failed to ensure flush directory: %v", err)
		return 1
	}

	auf, auditfileerr := helpers.OpenAuditLogFileUntilSuccessWithContext(ctx, auditlogpath)
	if auditfileerr != nil {
		log.Printf("Error: failed to open audit log file: %v", auditfileerr)
		return 1
	}

	w := auditevent.NewDefaultAuditEventWriter(auf)

	journaldChan := make(chan *types.LogEntry, journalEntryBufferSize)
	log.Println("Starting workers")

	wg.Add(1)
	go producer.JournaldProducer(ctx, &wg, journaldChan, bootID)

	wg.Add(1)
	go consumer.JournaldConsumer(ctx, &wg, journaldChan, w)
	wg.Wait()

	log.Println("All workers finished")
	return 0
}

func main() {
	os.Exit(mainWithExitCode())
}
