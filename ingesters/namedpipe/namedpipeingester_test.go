package namedpipe_test

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

func TestIngest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	pipePath := fmt.Sprintf("%s/named-pipe", tmpDir)
	err := syscall.Mkfifo(pipePath, 0o664)
	assert.NoError(t, err, "failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)

	logger := zap.NewExample().Sugar()
	h := health.NewSingleReadinessHealth(namedpipe.NamedPipeProcessorComponentName)
	np := namedpipe.NewNamedPipeIngester(logger, h)

	ctx := context.Background()
	callCount := 0
	done := make(chan struct{})
	//nolint
	callback := func(ctx2 context.Context, l string) error {
		callCount++
		if callCount == 5 {
			done <- struct{}{}
		}
		ctx.Value("")
		return nil
	}
	go func() {
		err := np.Ingest(ctx, pipePath, '\n', callback)
		if err != nil {
			return
		}
	}()

	go func() {
		file, err := os.OpenFile(pipePath, os.O_WRONLY, os.ModeNamedPipe)
		assert.NoError(t, err, "failed to initialize tests: Could not open %s named pipe", pipePath)

		for range []int{0, 1, 2, 3, 4} {
			_, err := file.WriteString("foo bar\n")
			assert.NoError(t, err, "error writing to pipe %s", pipePath)
		}
	}()

	<-done
	assert.Equal(t, 5, callCount)
}
