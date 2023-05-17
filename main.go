// audito-maldito is a daemon that monitors OpenSSH server logins and
// produces structured audit events describing what authenticated users
// did while logged in (e.g., what programs they executed).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/metal-toolbox/audito-maldito/cmd"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

func main() {
	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	args := os.Args[1:]

	for _, p := range args {
		if p == "--namedpipe" {
			return cmd.RunNamedPipe(ctx, os.Args, health.NewHealth(), nil)
		}
	}
	os.Stdout.WriteString("defaulting to journald command")
	return cmd.RunJournald(ctx, os.Args, health.NewHealth(), nil)
}
