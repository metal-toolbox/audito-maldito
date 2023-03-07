package common

import (
	"fmt"
	"os"
)

// GetNodeName returns the node name.
// It reads it from the NODE_NAME environment variable.
func GetNodeName() (string, error) {
	nodename := os.Getenv("NODE_NAME")

	if nodename == "" {
		var err error
		nodename, err = os.Hostname()
		if err != nil {
			return "", fmt.Errorf("error getting hostname: %w", err)
		}
	}

	return nodename, nil
}
