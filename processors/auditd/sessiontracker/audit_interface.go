package sessiontracker

import "github.com/elastic/go-libaudit/v2/aucoalesce"

// Auditor is the interface that wraps the AuditdEvent method.
// It allows the session tracker to audit events.
type Auditor interface {
	AuditdEvent(event *aucoalesce.Event) error
}
