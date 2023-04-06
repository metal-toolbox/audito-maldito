package testtools

import (
	"context"
	"fmt"
	"testing"

	"github.com/metal-toolbox/auditevent"
)

// TestAuditEncoder implements auditevent.EventEncoder for testing purposes.
type TestAuditEncoder struct {
	// Ctx is a context.Context that is checked before writing to
	// the events channel.
	//
	//nolint
	Ctx context.Context

	// Events is written to when Encode is called.
	Events chan<- *auditevent.AuditEvent

	// T is the current test's testing.T.
	T *testing.T

	// Err is an optional error that is returned when Encode is
	// called (only if Err is non-nil).
	Err error
}

func (o TestAuditEncoder) Encode(i interface{}) error {
	if o.Err != nil {
		return o.Err
	}

	event, ok := i.(*auditevent.AuditEvent)
	if !ok {
		o.T.Fatalf("failed to type assert event ('%T') as *auditevent.AuditEvent", i)
	}

	select {
	case o.Events <- event:
		return nil
	case <-o.Ctx.Done():
		return fmt.Errorf("testAuditEncoder.Encode timed-out while trying to write to events chan "+
			"(check channel capacity | cap: %d | len: %d) - %w", cap(o.Events), len(o.Events), o.Ctx.Err())
	}
}
