package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/app"
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

	return app.Run(ctx, os.Args, newLoggerFn)
}
