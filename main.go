package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/journald/consumer"
	"github.com/metal-toolbox/audito-maldito/internal/journald/producer"
)

func main() {
	var bootID string

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flag.StringVar(&bootID, "boot-id", "", "Boot-ID to read from the journal")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	flag.Parse()

	var wg sync.WaitGroup

	if err := common.EnsureFlushDirectory(); err != nil {
		log.Fatal(err)
	}

	journaldChan := make(chan *sdjournal.JournalEntry, 1000)
	log.Println("Starting workers")

	wg.Add(1)
	go producer.JournaldProducer(ctx, &wg, journaldChan, bootID)

	wg.Add(1)
	go consumer.JournaldConsumer(ctx, &wg, journaldChan)
	wg.Wait()

	log.Println("All workers finished")
}
