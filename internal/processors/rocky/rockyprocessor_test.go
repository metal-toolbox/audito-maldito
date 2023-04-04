package rocky_test

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/metal-toolbox/audito-maldito/internal/processors/rocky"
	"github.com/stretchr/testify/assert"
)

//go:embed test_files/secure.log
var secureLogs string

func TestRockyProcess(t *testing.T) {
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
		assert.Equal(t, pm.PID, "3894")
		assert.Contains(t, line, pm.LogEntry)
	}
}
