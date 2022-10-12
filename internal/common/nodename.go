package common

import (
	"errors"
	"os"
)

var (
	NoNodeNameGivenError = errors.New("no node name given")
)

// GetNodeName returns the node name.
// It reads it from the NODE_NAME environment variable.
func GetNodeName() (string, error) {
	nodename := os.Getenv("NODE_NAME")

	if nodename == "" {
		return "", NoNodeNameGivenError
	}

	return nodename, nil
}
