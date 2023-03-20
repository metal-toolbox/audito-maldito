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

	"github.com/metal-toolbox/audito-maldito/internal/app"
	"github.com/metal-toolbox/audito-maldito/internal/common"
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

	return app.Run(ctx, os.Args, common.NewHealth(), nil)
}
