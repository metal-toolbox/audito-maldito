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
	expSSHKeyType = "ssh-rsa"
	expSSHKeyFP   = "hoo ahh 22"
)

func TestRevokedPublicKeyByFile(t *testing.T) {
	t.Parallel()

	p, events := newRevokedLogSSHDProcessor(t,
		fmt.Sprintf("Authentication key %s %s revoked by file %s",
			expSSHKeyType, expSSHKeyFP, expFilePath))

	err := revokedPublicKeyByFile(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSSHKeyType, event.Subjects["keyType"])
		require.Equal(t, expSSHKeyFP, event.Subjects["fingerprint"])
		require.Equal(t, expFilePath, event.Subjects["filePath"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestRevokedPublicKeyByFile_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newRevokedLogSSHDProcessor(t, "nope")

	err := revokedPublicKeyByFile(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func TestRevokedPublicKeyByFileErr(t *testing.T) {
	t.Parallel()

	p, events := newRevokedLogSSHDProcessor(t,
		fmt.Sprintf("Error checking authentication key %s %s in revoked keys file %s",
			expSSHKeyType, expSSHKeyFP, expFilePath))

	err := revokedPublicKeyByFileErr(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSSHKeyType, event.Subjects["keyType"])
		require.Equal(t, expSSHKeyFP, event.Subjects["fingerprint"])
		require.Equal(t, expFilePath, event.Subjects["filePath"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestRevokedPublicKeyByFileErr_NoMatches(t *testing.T) {
	t.Parallel()

	p, events := newRevokedLogSSHDProcessor(t, "nope")

	err := revokedPublicKeyByFileErr(p)

	require.NoError(t, err)
	require.Empty(t, events)
}

func newRevokedLogSSHDProcessor(t *testing.T, logEntry string) (x *SshdProcessorer, y <-chan *auditevent.AuditEvent) {
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
