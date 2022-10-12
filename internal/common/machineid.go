package common

import (
	"os"
	"strings"
)

const (
	// MachineIDPath is the path to the machine-id file.
	MachineIDPath = "/etc/machine-id"
)

// GetMachineID returns the machine ID.
func GetMachineID() (string, error) {
	machineID, err := os.ReadFile(MachineIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(machineID)), nil
}
