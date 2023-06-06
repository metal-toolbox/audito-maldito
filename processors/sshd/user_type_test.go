package sshd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/require"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

// The linter made me do this, sorry.
const (
	expUsername = "foo foo"
	expSource   = "bar"
)

func TestUserTypeLogAuditFn(t *testing.T) {
	t.Parallel()

	logStrs := []string{
		"User u from s not allowed because not listed in AllowUsers",
		"User u not allowed because shell s does not exist",
		"User u not allowed because shell s is not executable",
		"User u from s not allowed because listed in DenyUsers",
		"User u from s not allowed because not in any group",
		"User u from s not allowed because a group is listed in DenyGroups",
		"User u from s not allowed because none of user's groups are listed in AllowGroups",
	}

	for _, logStr := range logStrs {
		p := &SshdProcessorer{logEntry: logStr}
		fn := userTypeLogAuditFn(p)

		if fn == nil {
			t.Fatalf("expected nil func for log str '%s' - got nil", logStr)
		}
	}
}

func TestProcessNotInAllowUsersEntry(t *testing.T) {
	t.Parallel()

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s from %s not allowed because not listed in AllowUsers",
			expUsername, expSource))

	err := processNotInAllowUsersEntry(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSource, event.Source.Value)
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserNonExistentShell(t *testing.T) {
	t.Parallel()

	expShell := "/bin/foo"

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s not allowed because shell %s does not exist",
			expUsername, expShell))

	err := userNonExistentShell(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expShell, event.Metadata.Extra["shell"])
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserNonExecutableShell(t *testing.T) {
	t.Parallel()

	expShell := "/bin/foo"

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s not allowed because shell %s is not executable",
			expUsername, expShell))

	err := userNonExecutableShell(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expShell, event.Metadata.Extra["shell"])
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserInDenyUsers(t *testing.T) {
	t.Parallel()

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s from %s not allowed because listed in DenyUsers",
			expUsername, expSource))

	err := userInDenyUsers(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSource, event.Source.Value)
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserNotInAnyGroup(t *testing.T) {
	t.Parallel()

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s from %s not allowed because not in any group",
			expUsername, expSource))

	err := userNotInAnyGroup(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSource, event.Source.Value)
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserGroupInDenyGroups(t *testing.T) {
	t.Parallel()

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s from %s not allowed because a group is listed in DenyGroups",
			expUsername, expSource))

	err := userGroupInDenyGroups(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSource, event.Source.Value)
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func TestUserGroupNotListedInAllowGroups(t *testing.T) {
	t.Parallel()

	p, events := newUserLogSSHDProcessor(t,
		fmt.Sprintf("User %s from %s not allowed because none of user's groups are listed in AllowGroups",
			expUsername, expSource))

	err := userGroupNotListedInAllowGroups(p)

	require.NoError(t, err)

	select {
	case event := <-events:
		require.Equal(t, expSource, event.Source.Value)
		require.Equal(t, expUsername, event.Subjects["loggedAs"])
	default:
		t.Fatal("expected a channel write - got none")
	}
}

func newUserLogSSHDProcessor(t *testing.T, logEntry string) (x *SshdProcessorer, y <-chan *auditevent.AuditEvent) {
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

func TestUserLogToAuditEvent(t *testing.T) {
	t.Parallel()

	username := "foo"
	source := "bar"
	pid := "777"
	nodeName := "x"
	machineID := "y"
	when := time.Now()

	event := userLogToAuditEvent(username, source, &SshdProcessorer{
		nodeName:  nodeName,
		machineID: machineID,
		when:      when,
		pid:       pid,
	})

	require.Equal(t, username, event.Subjects["loggedAs"])
	require.Equal(t, common.UnknownUser, event.Subjects["userID"])
	require.Equal(t, pid, event.Subjects["pid"])
	require.Equal(t, source, event.Source.Value)
	require.Equal(t, nodeName, event.Target["host"])
	require.Equal(t, machineID, event.Target["machine-id"])
	require.Equal(t, when, event.LoggedAt)
}
