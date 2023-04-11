package namedpipe

import (
	"bufio"
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

type NamedPipeIngester struct{}

type Callback func(context.Context, string) error

func (n *NamedPipeIngester) Ingest(
	ctx context.Context,
	filePath string,
	delim byte,
	callback Callback,
	logger *zap.SugaredLogger,
	h *common.Health,
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

	logger.Infof("Successfully opened %s", filePath)

	if err != nil {
		return err
	}

	h.OnReady()
	r := bufio.NewReader(file)
	go (func() {
		<-ctx.Done()
		file.Close()
	})()

	for {
		line, err := r.ReadString(delim)
		if err != nil {
			logger.Errorf("error reading from ", file.Name())
			return err
		}
		err = callback(ctx, line)
		if err != nil {
			return err
		}
	}
}
