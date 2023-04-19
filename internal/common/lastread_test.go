package common

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DoGetLastRead(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()

	t.Run("InvalidFile", func(t *testing.T) {
		t.Parallel()

		fPath := filepath.Join(tmpdir, "never gonna give you up")

		_, err := doGetLastRead(fPath)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("EmptyFile", func(t *testing.T) {
		t.Parallel()

		fPath := filepath.Join(tmpdir, filepath.Base(t.Name()))

		err := os.WriteFile(fPath, []byte{}, 0o600)
		assert.NoError(t, err)

		_, err = doGetLastRead(fPath)
		assert.ErrorIs(t, err, strconv.ErrSyntax)
	})

	t.Run("NotAnInt", func(t *testing.T) {
		t.Parallel()

		fPath := filepath.Join(tmpdir, filepath.Base(t.Name()))

		err := os.WriteFile(fPath, []byte{0x41, 0x41, 0x41, 0x41, 0x0a}, 0o600)
		assert.NoError(t, err)

		_, err = doGetLastRead(fPath)
		assert.ErrorIs(t, err, strconv.ErrSyntax)
	})

	t.Run("ValidInt", func(t *testing.T) {
		t.Parallel()

		fPath := filepath.Join(tmpdir, filepath.Base(t.Name()))

		var exp uint64 = 1666371243954575

		err := os.WriteFile(fPath, []byte(strconv.Itoa(int(exp))), 0o600)
		assert.NoError(t, err)

		i, err := doGetLastRead(fPath)
		assert.NoError(t, err)

		assert.Equal(t, exp, i)
	})
}

func TestEnsureFlushDirectory_DirAlreadyExists(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "x")

	err := ensureFlushDirectory(filePath)
	assert.Nil(t, err)
}

func TestEnsureFlushDirectory_DirDoesNotExist(t *testing.T) {
	t.Parallel()

	filePath := filepath.Join(t.TempDir(), "does-not-exist", "some-file")

	err := ensureFlushDirectory(filePath)
	assert.Nil(t, err)

	info, err := os.Stat(filepath.Dir(filePath))
	assert.Nil(t, err)

	assert.Equal(t, info.Mode().Perm(), fs.FileMode(flushDirPerms))
}
