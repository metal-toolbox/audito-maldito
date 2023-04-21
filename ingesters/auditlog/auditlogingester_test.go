package auditlog_test

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/auditlog"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/stretchr/testify/assert"
)

func TestIngest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	pipePath := fmt.Sprintf("%s/audit-pipe", tmpDir)
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	err = syscall.Mkfifo(pipePath, 0664)
	if err != nil {
		t.Errorf("failed to initialize tests: Could not create %s/%s named pipe", tmpDir, pipePath)
	}

	auditLogChanBufSize := 10000
	auditLogChan := make(chan string, auditLogChanBufSize)
	sugar := zap.NewExample().Sugar()
	h := health.NewSingleReadinessHealth("auditlog")
	ali := auditlog.AuditLogIngester{
		FilePath:     pipePath,
		AuditLogChan: auditLogChan,
		Logger:       sugar,
		Health:       h,
	}

	ctx := context.Background()
	go func() {
		ali.Ingest(ctx)
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

	readCount := 0
	for {
		select {
		case line := <-auditLogChan:
			assert.Equal(t, "foo bar\n", line)
			readCount++
		}

		if readCount == 5 {
			break
		}
	}
}
