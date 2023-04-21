package syslog

import (
	"context"
	"strings"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type SyslogIngester struct {
	namedPipeIngester namedpipe.NamedPipeIngester
	FilePath          string
	SshdProcessor     sshd.SshdProcessor
	Logger            *zap.SugaredLogger
	Health            *health.Health
}

func (s *SyslogIngester) Ingest(ctx context.Context) error {
	return s.namedPipeIngester.Ingest(ctx, s.FilePath, '\n', s.Process, s.Logger, s.Health)
}

func (s *SyslogIngester) Process(ctx context.Context, line string) error {
	sm := s.ParseSyslogMessage(line)
	return s.SshdProcessor.ProcessSshdLogEntry(ctx, sm)
}

func (s *SyslogIngester) ParseSyslogMessage(entry string) sshd.SshdLogEntry {
	entrySplit := strings.Split(entry, " ")
	pid := entrySplit[0]
	logMsg := strings.Join(entrySplit[1:], " ")
	logMsg = strings.TrimLeft(logMsg, " ")
	return sshd.SshdLogEntry{PID: pid, Message: logMsg}
}
