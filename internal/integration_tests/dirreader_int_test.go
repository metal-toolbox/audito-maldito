//go:build int

package integration_tests

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/auditd"
)

func TestStartLogDirReader(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tempDirPath := t.TempDir()

	_, err := auditd.StartLogDirReader(ctx, tempDirPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStartLogDirReader_EmptyDirPathErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	_, err := auditd.StartLogDirReader(ctx, "")
	assert.NotNil(t, err)
}

func TestStartLogDirReader_ReadDirErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	_, err := auditd.StartLogDirReader(ctx, "/Function TestRotatingFile_Lifecycle missing the call to method parallel")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
