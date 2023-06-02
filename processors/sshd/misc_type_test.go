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

const (
	expPort     = "666"
	expFilePath = "/home/cb/buh"
)

func TestRootLoginRefused(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t,
		fmt.Sprintf("ROOT LOGIN REFUSED FROM %s port %s",
			source, expPort))

	err := rootLoginRefused(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, expPort, event.Source.Extra["port"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestRootLoginRefused_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t, "nope")

	err := rootLoginRefused(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func TestBadOwnerOrModesForHostFile(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t,
		fmt.Sprintf("Authentication refused for %s: bad owner or modes for %s",
			username, expFilePath))

	err := badOwnerOrModesForHostFile(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, username, event.Subjects["loggedAs"])
		require.Equal(t, expFilePath, event.Subjects["filePath"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestBadOwnerOrModesForHostFile_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t, "nope")

	err := badOwnerOrModesForHostFile(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func TestMaxAuthAttemptsExceeded(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t,
		fmt.Sprintf("maximum authentication attempts exceeded for %s from %s port %s ssh2",
			username, source, expPort))

	err := maxAuthAttemptsExceeded(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, username, event.Subjects["loggedAs"])
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, expPort, event.Source.Extra["port"])

	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestMaxAuthAttemptsExceeded_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t, "nope")

	err := maxAuthAttemptsExceeded(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func TestFailedPasswordAuth(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t,
		fmt.Sprintf("Failed password for %s from %s port %s ssh2",
			username, source, expPort))

	err := failedPasswordAuth(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, username, event.Subjects["loggedAs"])
		require.Equal(t, source, event.Source.Value)
		require.Equal(t, expPort, event.Source.Extra["port"])

	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestFailedPasswordAuth_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newMiscLogSSHDProcessor(t, "nope")

	err := failedPasswordAuth(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func newMiscLogSSHDProcessor(t *testing.T, logEntry string) (x *SshdProcessorer, y <-chan *auditevent.AuditEvent) {
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
