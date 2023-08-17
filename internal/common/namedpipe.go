package common

import (
	"errors"
	"os"
)

var errNotNamedPipe = errors.New("not a named pipe")

// IsNamedPipe returns a non-nil error if filePath cannot be stat'ed
// or if it is not a named pipe.
func IsNamedPipe(filePath string) error {
	sshdLogFileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	if (sshdLogFileInfo.Mode() & os.ModeNamedPipe) == os.ModeNamedPipe {
		return nil
	}

	return errNotNamedPipe
}
