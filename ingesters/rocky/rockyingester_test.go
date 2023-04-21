package rocky_test

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/ingesters/rocky"
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
