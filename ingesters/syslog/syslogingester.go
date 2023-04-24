package syslog

import (
	"context"
	"strings"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

func NewSyslogIngester(
	filePath string,
	sshdProcessor sshd.SshdProcessor,
	namedPipeIngester namedpipe.NamedPipeIngester,
) SyslogIngester {
	return SyslogIngester{
		FilePath:          filePath,
		SshdProcessor:     sshdProcessor,
		namedPipeIngester: namedPipeIngester,
	}
}

type SyslogIngester struct {
	namedPipeIngester namedpipe.NamedPipeIngester
	FilePath          string
	SshdProcessor     sshd.SshdProcessor
}

func (s *SyslogIngester) Ingest(ctx context.Context) error {
	return s.namedPipeIngester.Ingest(ctx, s.FilePath, '\n', s.Process)
}

func (s *SyslogIngester) Process(ctx context.Context, line string) error {
	sm := s.ParseSyslogMessage(line)
	return s.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
}

// ParseSyslogMessage expects a message in the form of "<PID> <Message>".
func (s *SyslogIngester) ParseSyslogMessage(entry string) sshd.SshdLogEntry {
	minimumEntrySplitLength := 2
	entrySplit := strings.Split(entry, " ")

	if len(entrySplit) < minimumEntrySplitLength {
		return sshd.SshdLogEntry{}
	}

	pid := entrySplit[0]
	logMsg := strings.Join(entrySplit[1:], " ")
	logMsg = strings.TrimLeft(logMsg, " ")
	return sshd.SshdLogEntry{PID: pid, Message: logMsg}
}
