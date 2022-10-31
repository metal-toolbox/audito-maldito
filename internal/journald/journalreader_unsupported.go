//go:build !linux
// +build !linux

package journald

import (
	"errors"
	"log"

	"github.com/metal-toolbox/audito-maldito/internal/util"
)

func newJournalReader(bootID string, distro util.DistroType, logger *log.Logger) (JournalReader, error) {
	return nil, errors.New("unsupported platform")
}
