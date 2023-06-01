package sshd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/require"

	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

const dnsName = "foo.com"

func TestNastyPTRRecord(t *testing.T) {
	t.Parallel()

	p, events := newDNSLogSSHDProcessor(t,
		fmt.Sprintf("Nasty PTR record %q is set up for %s, ignoring",
			dnsName, source))

	err := nastyPTRRecord(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, dnsName, event.Source.Extra["dns"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestNastyPTRRecord_NoMatch(t *testing.T) {
	t.Parallel()

	p, _ := newDNSLogSSHDProcessor(t, "nope")

	err := nastyPTRRecord(p)

	require.NoError(t, err)
}

func TestReverseMappingCheckFailed(t *testing.T) {
	t.Parallel()

	p, events := newDNSLogSSHDProcessor(t,
		fmt.Sprintf("reverse mapping checking getaddrinfo for %s [%s] failed.",
			dnsName, source))

	err := reverseMappingCheckFailed(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, dnsName, event.Source.Extra["dns"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestReverseMappingCheckFailed_NoMatch(t *testing.T) {
	t.Parallel()

	p, _ := newDNSLogSSHDProcessor(t, "nope")

	err := reverseMappingCheckFailed(p)

	require.NoError(t, err)
}

func TestDoesNotMapBackToAddr(t *testing.T) {
	t.Parallel()

	p, events := newDNSLogSSHDProcessor(t,
		fmt.Sprintf("Address %s maps to %s, but this does not map back to the address.",
			source, dnsName))

	err := doesNotMapBackToAddr(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, dnsName, event.Source.Extra["dns"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestDoesNotMapBackToAddr_NoMatch(t *testing.T) {
	t.Parallel()

	p, _ := newDNSLogSSHDProcessor(t, "nope")

	err := doesNotMapBackToAddr(p)

	require.NoError(t, err)
}

func newDNSLogSSHDProcessor(t *testing.T, logEntry string) (x *SshdProcessorer, y <-chan *auditevent.AuditEvent) {
	t.Helper()

	events := make(chan *auditevent.AuditEvent, 1)

	p := &SshdProcessorer{
		logEntry:  logEntry,
		nodeName:  "a",
		machineID: "b",
		when:      time.Now(),
		pid:       "c",
		eventW: auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
			Ctx:    context.Background(),
			Events: events,
			T:      t,
		}),
	}

	return p, events
}
