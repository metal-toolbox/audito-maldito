package main

import (
	"context"
	"flag"
	"github.com/fsnotify/fsnotify"
	"log"
	"os"
	"os/signal"
)

func main() {
	err := mainWithError()
	if err != nil {
		log.Fatalln(err)
	}
}

func mainWithError() error {
	dirPath := flag.String("d", "", "")

	flag.Parse()

	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			log.Fatalf("please set '-%s' - %s", f.Name, f.Usage)
		}
	})

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	err = watcher.Add(*dirPath)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-watcher.Events:
			log.Printf("event: %s", event.String())
		}
	}
}
