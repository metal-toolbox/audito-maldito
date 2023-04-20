//go:build !linux
// +build !linux

package journald

import (
	"errors"

	"github.com/metal-toolbox/audito-maldito/internal/util"
)

func newJournalReader(string, util.DistroType, uint64) (JournalReader, error) {
	return nil, errors.New("unsupported platform")
}
