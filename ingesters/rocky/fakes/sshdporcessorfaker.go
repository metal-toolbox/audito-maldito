package fakes

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

type SshdProcessorFaker struct {
	CountChan   chan int
	count       int
	ExpectedPID string
}

func (s *SshdProcessorFaker) ProcessSshdLogEntry(ctx context.Context, sm sshd.SshdLogEntry) error {
	s.count += 1
	s.CountChan <- s.count
	if len(sm.Message) < 1 {
		return fmt.Errorf("message should be greater than 1")
	}

	if sm.PID != s.ExpectedPID {
		return fmt.Errorf("expected PID should be %s", s.ExpectedPID)
	}
	return nil
}
