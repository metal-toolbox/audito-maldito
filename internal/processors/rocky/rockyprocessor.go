package rocky

import (
	"context"
	"fmt"
	"regexp"

	"github.com/metal-toolbox/audito-maldito/internal/processors"
)

type RockyProcessor struct {
}

var pidRE = regexp.MustCompile(`sshd\[(?P<PROCID>\w+)\]: (?P<MSG>.+)`)

func (r *RockyProcessor) Process(ctx context.Context, line string) (processors.ProcessEntryMessage, error) {
	pidMatches := pidRE.FindStringSubmatch(line)
	if pidMatches == nil {
		return processors.ProcessEntryMessage{}, fmt.Errorf("no pid")
	}

	return processors.ProcessEntryMessage{PID: pidMatches[1], LogEntry: pidMatches[2]}, nil
}
