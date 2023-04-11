package fakes

import (
	"github.com/elastic/go-libaudit/v2/aucoalesce"

	"github.com/metal-toolbox/audito-maldito/internal/auditd/sessiontracker"
)

var _ sessiontracker.Auditor = &FakeAuditor{}

// FakeAuditor is a fake Auditor. It allows you to set a callback
// that is called when AuditdEvent is called.
type FakeAuditor struct {
	cb func(event *aucoalesce.Event) error
}

func NewFakeAuditor(cb func(event *aucoalesce.Event) error) *FakeAuditor {
	return &FakeAuditor{
		cb: cb,
	}
}

func (f *FakeAuditor) AuditdEvent(event *aucoalesce.Event) error {
	return f.cb(event)
}
