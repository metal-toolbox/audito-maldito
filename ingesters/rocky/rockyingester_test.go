package rocky_test

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/ingesters/rocky"
	"github.com/metal-toolbox/audito-maldito/ingesters/rocky/fakes"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

//go:embed testdata/secure.log
var secureLogs string

// testSshdPid is the pid used in our test files.
var testSshdPid = "3894"

func TestRockyProcess(t *testing.T) {
	t.Parallel()
	r := rocky.RockyIngester{}
	for _, line := range strings.Split(secureLogs, "\n") {
		logEntry := r.ParseRockySecureMessage(line)
		if logEntry.PID == "" {
			continue
		}

		if logEntry.Message == "" {
			continue
		}

		assert.Equal(t, logEntry.PID, testSshdPid)
		assert.Contains(t, line, logEntry.Message)
	}
}

func TestIngest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	pipePath := fmt.Sprintf("%s/secure-pipe", tmpDir)
	err := syscall.Mkfifo(pipePath, 0o664)
	if err != nil {
		assert.Error(t, err, "failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)
	}
	countChan := make(chan int)
	expectedPID := "10"
	h := health.NewSingleReadinessHealth("secure")
	logger := zap.NewExample().Sugar()
	namedPipeIngester := namedpipe.NewNamedPipeIngester(logger, h)
	ri := rocky.NewRockyIngester(
		pipePath,
		&fakes.SshdProcessorFaker{CountChan: countChan, ExpectedPID: expectedPID},
		namedPipeIngester,
	)

	ctx := context.Background()
	go func() {
		err := ri.Ingest(ctx)
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
			_, err := file.WriteString(fmt.Sprintf("sshd[%s]:", expectedPID) + " foo bar\n")
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
