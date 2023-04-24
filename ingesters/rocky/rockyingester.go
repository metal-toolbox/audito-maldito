package rocky

import (
	"context"
	"regexp"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

func NewRockyIngester(
	filePath string,
	sshdProcessor sshd.SshdProcessor,
	namedPipeIngester namedpipe.NamedPipeIngester,
) RockyIngester {
	return RockyIngester{
		FilePath:          filePath,
		SshdProcessor:     sshdProcessor,
		namedPipeIngester: namedPipeIngester,
	}
}

type RockyIngester struct {
	namedPipeIngester namedpipe.NamedPipeIngester
	FilePath          string
	SshdProcessor     sshd.SshdProcessor
}

func (r *RockyIngester) Ingest(ctx context.Context) error {
	return r.namedPipeIngester.Ingest(ctx, r.FilePath, '\n', r.Process)
}

func (r *RockyIngester) Process(ctx context.Context, line string) error {
	sm := r.ParseRockySecureMessage(line)
	return r.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
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

func (r *RockyIngester) ParseRockySecureMessage(line string) sshd.SshdLogEntry {
	messageMatches := pidRE.FindStringSubmatch(line)
	if messageMatches == nil {
		return sshd.SshdLogEntry{}
	}

	if len(messageMatches) < numberOfMatches {
		return sshd.SshdLogEntry{}
	}

	return sshd.SshdLogEntry{PID: messageMatches[1], Message: messageMatches[2]}
}
