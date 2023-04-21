package namedpipe_test

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"
)

func TestIngest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	pipePath := fmt.Sprintf("%s/named-pipe", tmpDir)
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	err = syscall.Mkfifo(pipePath, 0664)
	if err != nil {
		t.Errorf("failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)
	}

	sugar := zap.NewExample().Sugar()
	h := health.NewSingleReadinessHealth("namedpipe")
	np := namedpipe.NamedPipeIngester{}

	ctx := context.Background()
	callCount := 0
	done := make(chan struct{})
	callback := func(ctx context.Context, l string) error {
		callCount++
		if callCount == 5 {
			done <- struct{}{}
		}
		return nil
	}
	go func() {
		np.Ingest(ctx, pipePath, '\n', callback, sugar, h)
	}()

	go func() {
		file, err := os.OpenFile(pipePath, os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			t.Errorf("failed to initialize tests: Could not open %s named pipe", pipePath)
		}

		for range []int{0, 1, 2, 3, 4} {
			_, err := file.WriteString("foo bar\n")
			if err != nil {
				t.Errorf("error writing to pipe %s", pipePath)
			}
		}
	}()

	<-done
	assert.Equal(t, 5, callCount)
}
