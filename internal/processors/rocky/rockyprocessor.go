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
	entryMatches := pidRE.FindStringSubmatch(line)
	if entryMatches == nil {
		return processors.ProcessEntryMessage{}, nil
	}

	if len(entryMatches) < 3 {
		return processors.ProcessEntryMessage{}, fmt.Errorf("match group less than 3")
	}

	return processors.ProcessEntryMessage{PID: entryMatches[1], LogEntry: entryMatches[2]}, nil
}
