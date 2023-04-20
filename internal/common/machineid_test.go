package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMachineID(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "")
	require.Nil(t, err)
	defer f.Close()

	_, err = f.WriteString("foobar")
	require.Nil(t, err)

	id, err := getMachineID(f.Name())
	require.Nil(t, err)

	assert.Equal(t, "foobar", id)
}

func TestGetMachineID_TrimSpace(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "")
	require.Nil(t, err)
	defer f.Close()

	_, err = f.WriteString("    foobar        \n")
	require.Nil(t, err)

	id, err := getMachineID(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "foobar", id)
}

func TestGetMachineID_IDFileDoesNotExist(t *testing.T) {
	t.Parallel()

	_, err := getMachineID("/tmp/_______________")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
