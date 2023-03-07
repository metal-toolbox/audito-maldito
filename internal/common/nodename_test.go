package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:paralleltest // We can't ensure env variable consistency in parallel tests.
func TestGetNodeNameWithEnvVar(t *testing.T) {
	t.Setenv("NODE_NAME", "test")

	nodename, err := GetNodeName()
	assert.NoError(t, err, "error getting node name")

	assert.Equal(t, "test", nodename, "node name is not equal")
}

//nolint:paralleltest // We can't ensure env variable consistency in parallel tests.
func TestGetNodeNameWithoutEnvVar(t *testing.T) {
	hostname, err := os.Hostname()
	assert.NoError(t, err, "error getting hostname")

	nodename, err := GetNodeName()
	assert.NoError(t, err, "error getting node name")

	assert.Equal(t, hostname, nodename, "node name is not equal")
}
