package namedpipe

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/health"
)

const (
	// NamedPipeProcessorComponentName is the name of the component
	// that reads from a named pipe. This is used in the health check.
	NamedPipeProcessorComponentName = "named-pipe-processor"
)

func NewNamedPipeIngester(logger *zap.SugaredLogger, h *health.Health) NamedPipeIngester {
	return NamedPipeIngester{
		Logger: logger,
		Health: h,
	}
}

type NamedPipeIngester struct {
	Logger *zap.SugaredLogger
	Health *health.Health
}

type Callback func(context.Context, string) error

func (n *NamedPipeIngester) Ingest(
	ctx context.Context,
	filePath string,
	delim byte,
	callback Callback,
) error {
	var file *os.File
	var err error
	ready := make(chan struct{})

	// os.OpenFile blocks. Put in go routine so we can gracefully exit.
	go func() {
		file, err = os.OpenFile(filePath, os.O_RDONLY, os.ModeNamedPipe)
		close(ready)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
	}

	if err != nil {
		return err
	}

	n.Logger.Infof("Successfully opened %s", filePath)
	defer file.Close()

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	n.Health.OnReady(fmt.Sprintf("%s-%s", fileInfo.Name(), NamedPipeProcessorComponentName))
	r := bufio.NewReader(file)

	for {
		line, err := r.ReadString(delim)
		if err != nil {
			n.Logger.Errorf("error reading from ", file.Name())
			return err
		}
		err = callback(ctx, line)
		if err != nil {
			return err
		}
	}
}
