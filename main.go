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

	"go.uber.org/zap"

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

	newLoggerFn := func() (*zap.Logger, error) {
		return zap.NewProduction()
	}

	return app.Run(ctx, os.Args, common.NewHealth(), newLoggerFn)
}
