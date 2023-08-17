package common

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsNamedPipe(t *testing.T) {
	t.Parallel()

	namedPipePath := filepath.Join(t.TempDir(), "foo.pipe")

	require.NoError(t, syscall.Mkfifo(namedPipePath, 0o600))

	require.NoError(t, IsNamedPipe(namedPipePath))
}

func TestIsNamedPipe_RegularFile(t *testing.T) {
	t.Parallel()

	regularFilePath := filepath.Join(t.TempDir(), "foo.txt")

	regularFile, err := os.Create(regularFilePath)
	require.NoError(t, err)
	_ = regularFile.Close()

	require.ErrorIs(t, IsNamedPipe(regularFilePath), errNotNamedPipe)
}

func TestIsNamedPipe_StatFailure(t *testing.T) {
	t.Parallel()

	regularFilePath := filepath.Join(t.TempDir(), string([]byte{0x90, 0x90, 0x90, 0x90}))

	var expErr *os.PathError

	require.ErrorAs(t, IsNamedPipe(regularFilePath), &expErr)
}
