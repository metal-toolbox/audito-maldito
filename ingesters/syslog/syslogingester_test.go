package syslog_test

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/syslog"
	"github.com/metal-toolbox/audito-maldito/ingesters/syslog/fakes"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

func TestIngest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	pipePath := fmt.Sprintf("%s/sshd-pipe", tmpDir)

	defer func() {
		os.RemoveAll(tmpDir)
	}()
	err = syscall.Mkfifo(pipePath, 0664)
	if err != nil {
		t.Errorf("failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)
	}
	countChan := make(chan int)
	expectedPID := "10"
	h := health.NewSingleReadinessHealth("sshd")
	sugar := zap.NewExample().Sugar()

	ctx := context.Background()
	sli := syslog.SyslogIngester{
		FilePath:      pipePath,
		SshdProcessor: &fakes.SshdProcessorFaker{CountChan: countChan, ExpectedPID: expectedPID},
		Logger:        sugar,
		Health:        h,
	}

	go func() {
		sli.Ingest(ctx)
	}()

	go func() {
		file, err := os.OpenFile(pipePath, os.O_WRONLY, os.ModeNamedPipe)
		if err != nil {
			t.Errorf("failed to initialize tests: Could not open %s named pipe", pipePath)
		}

		for range []int{0, 1, 2, 3, 4} {
			_, err := file.WriteString(expectedPID + " foo bar\n")
			if err != nil {
				t.Errorf("error writing to pipe %s", pipePath)
			}
		}
	}()

	for {
		select {
		case count := <-countChan:
			if count == 5 {
				return
			}
		}
	}
}
