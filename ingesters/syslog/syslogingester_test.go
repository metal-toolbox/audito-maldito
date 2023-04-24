package syslog_test

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog/fakes"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

func TestIngest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	pipePath := fmt.Sprintf("%s/sshd-pipe", tmpDir)
	err := syscall.Mkfifo(pipePath, 0o664)
	if err != nil {
		assert.Error(t, err, "failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)
	}
	countChan := make(chan int)
	expectedPID := "10"
	h := health.NewSingleReadinessHealth("sshd")
	logger := zap.NewExample().Sugar()
	namedPipeIngester := namedpipe.NewNamedPipeIngester(logger, h)
	sli := syslog.NewSyslogIngester(
		pipePath,
		&fakes.SshdProcessorFaker{CountChan: countChan, ExpectedPID: expectedPID},
		namedPipeIngester,
	)

	ctx := context.Background()
	go func() {
		err := sli.Ingest(ctx)
		if err != nil {
			return
		}
	}()

	go func() {
		file, err := os.OpenFile(pipePath, os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			assert.Error(t, err, "failed to initialize tests: Could not open %s named pipe", pipePath)
		}

		for range []int{0, 1, 2, 3, 4} {
			_, err := file.WriteString(expectedPID + " foo bar\n")
			if err != nil {
				assert.Error(t, err, "error writing to pipe %s", pipePath)
			}
		}
	}()

	for count := range countChan {
		if count == 5 {
			return
		}
	}
}
