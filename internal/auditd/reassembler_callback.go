package auditd

import (
	"fmt"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"

	"github.com/metal-toolbox/audito-maldito/internal/auditd/sessiontracker"
)

var _ libaudit.Stream = &reassemblerCB{}

// reassemblerCB implements the libaudit.Stream interface.
type reassemblerCB struct {
	au     sessiontracker.Auditor
	errors chan<- error
	after  time.Time
}

func (s *reassemblerCB) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		s.errors <- &reassemblerCBError{
			message: fmt.Sprintf("failed to coalesce audit messages - %s", err),
			inner:   err,
		}

		return
	}

	if event.Timestamp.Before(s.after) {
		return
	}

	aucoalesce.ResolveIDs(event)

	if err := s.au.AuditdEvent(event); err != nil {
		s.errors <- &reassemblerCBError{
			message: fmt.Sprintf("failed to audit audit event - %s", err),
			inner:   err,
		}
	}
}

func (s *reassemblerCB) EventsLost(count int) {
	logger.Errorf("lost %d auditd events during reassembly", count)
}
