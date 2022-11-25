package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/metal-toolbox/audito-maldito/internal/auditd"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln(err)
	}
}

func mainWithError() error {
	flag.Parse()

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

	dr, err := auditd.DirReaderFor(ctx, "/var/log/audit")
	if err != nil {
		return err
	}
	defer func() {
		<-dr.Exited()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-dr.Exited():
			return err
		case line := <-dr.Lines():
			log.Println(line)
		}
	}
}
