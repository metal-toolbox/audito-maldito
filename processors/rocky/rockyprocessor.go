package rocky

import (
	"context"
	"fmt"
	"regexp"

	sshd "github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type RockyProcessor struct {
	SshdProcessor *sshd.SshdProcessor
}

// pidRE regex matches a sshd log line extracting the procid and message into a match group
// example log line:
//
//	Apr  3 15:48:03 localhost sshd[3894]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
//
// regex match:
//
//	entryMatches[0]: sshd[3894]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
//	entryMatches[1]: 3894
//	entryMatches[2]: Connection closed by authenticating user user 127.0.0.1 port 41796 [preauth]
var pidRE = regexp.MustCompile(`sshd\[(?P<PROCID>\w+)\]: (?P<MSG>.+)`)

// numberOfMatches should have 3 match groups.
var numberOfMatches = 3

func (r *RockyProcessor) Process(ctx context.Context, line string) (sshd.SshdLogEntry, error) {
	entryMatches := pidRE.FindStringSubmatch(line)
	if entryMatches == nil {
		return sshd.SshdLogEntry{}, nil
	}

	if len(entryMatches) < numberOfMatches {
		return sshd.SshdLogEntry{}, fmt.Errorf("match group less than 3")
	}

	return sshd.SshdLogEntry{PID: entryMatches[1], Message: entryMatches[2]}, nil
}
