package rocky_test

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/processors/rocky"
)

//go:embed testdata/secure.log
var secureLogs string

// testSshdPid is the pid used in our test files.
var testSshdPid = "3894"

func TestRockyProcess(t *testing.T) {
	t.Parallel()
	r := rocky.RockyProcessor{}
	ctx := context.Background()
	for _, line := range strings.Split(secureLogs, "\n") {
		pm, err := r.Process(ctx, line)
		if err != nil {
			if err.Error() != "not sshd entry" {
				assert.Failf(t, "failed to process line: %s", line)
			}
			continue
		}

		if pm.PID == "" {
			continue
		}

		assert.Equal(t, pm.PID, testSshdPid)
		assert.Contains(t, line, pm.LogEntry)
	}
}
