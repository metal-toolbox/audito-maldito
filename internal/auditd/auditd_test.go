package auditd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func TestMain(m *testing.M) {
	logger = zap.NewNop().Sugar()

	os.Exit(m.Run())
}

func TestAuditd_RemoteUserLoginFirst(t *testing.T) {
	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin)
	events := make(chan *auditevent.AuditEvent, auditdNumResultingEvents)

	r, w := io.Pipe()
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	a := Auditd{
		Source: r,
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&testAuditEncoder{
			ctx:    ctx,
			events: events,
		}),
	}

	exited := make(chan error, 1)

	go func() {
		exited <- a.Read(ctx)
	}()

	sshLogin := newSshdJournaldAuditEvent("user", auditdSshdPid)

	select {
	case logins <- sshLogin:
	case err := <-exited:
		t.Fatalf("read exited unexpectedly while writing remote user login to logins chan - %v", err)
	}

	writesDone := make(chan error, 1)
	go func() {
		// Perform writes in a separate Go routine in order to
		// handle potential scenarios where the writes block.
		// This allows the context to timeout and the test
		// to fail.
		_, err := w.Write([]byte(auditdLogin))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(auditdExecLs))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(auditdLogout))
		if err != nil {
			writesDone <- err
			return
		}

		close(writesDone)
	}()

	select {
	case err := <-exited:
		t.Fatalf("read exited unexpectedly - %v", err)
	case err := <-writesDone:
		if err != nil {
			t.Fatalf("auditd writes failed - %s", err)
		}
	}

	checker := goodAuditdEventsChecker{
		login:  sshLogin,
		events: events,
		exited: exited,
		t:      t,
	}

	checker.checkAuditdEvents()
}

type testAuditEncoder struct {
	ctx    context.Context
	events chan<- *auditevent.AuditEvent
}

func (o testAuditEncoder) Encode(i interface{}) error {
	event, ok := i.(*auditevent.AuditEvent)
	if !ok {
		return fmt.Errorf("failed to type assert event ('%T') as *auditevent.AuditEvent", i)
	}

	select {
	case o.events <- event:
		return nil
	case <-o.ctx.Done():
		return fmt.Errorf("testAuditEncoder.Encode timed-out while trying to write to events chan "+
			"(check channel capacity | cap: %d | len: %d) - %w", cap(o.events), len(o.events), o.ctx.Err())
	}
}

func newSshdJournaldAuditEvent(unixAccountName string, pid int) common.RemoteUserLogin {
	usernameFromCert := "x"

	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: "10.0.2.2",
			Extra: map[string]any{
				"port": "666",
			},
		},
		auditevent.OutcomeSucceeded,
		map[string]string{
			"userID":   usernameFromCert,
			"loggedAs": unixAccountName,
			"pid":      strconv.Itoa(pid),
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       "localhost",
		"machine-id": "foobar",
	})

	evt.LoggedAt = time.Now()

	return common.RemoteUserLogin{
		Source:     evt,
		PID:        pid,
		CredUserID: usernameFromCert,
	}
}

type goodAuditdEventsChecker struct {
	login  common.RemoteUserLogin
	events <-chan *auditevent.AuditEvent
	exited <-chan error
	t      *testing.T
}

func (o goodAuditdEventsChecker) checkAuditdEvents() {
	i := 0

	for {
		select {
		case err := <-o.exited:
			o.t.Fatalf("read exited unexpectedly - %v", err)
		case event := <-o.events:
			var extra map[string]interface{}

			switch i {
			case 0:
				extra = map[string]interface{}{
					"action": "acquired-credentials",
					"how":    "/usr/sbin/sshd",
					"object": aucoalesce.Object{
						Type:      "user-session",
						Primary:   "ssh",
						Secondary: "10.0.2.2",
					},
				}
			case 1:
				extra = map[string]interface{}{
					"action": "logged-in",
					"how":    "/usr/sbin/sshd",
					"object": aucoalesce.Object{
						Type:      "user-session",
						Primary:   "/dev/pts/3",
						Secondary: "10.0.2.2",
					},
				}
			case 2:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "bash",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/bin/bash",
						Secondary: "",
					},
				}
			case 3:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/locale-check",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/locale-check",
						Secondary: "",
					},
				}
			case 4:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/locale",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/locale",
						Secondary: "",
					},
				}
			case 5:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/dash",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/lesspipe",
						Secondary: "",
					},
				}
			case 6:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/basename",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/basename",
						Secondary: "",
					},
				}
			case 7:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/dirname",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/dirname",
						Secondary: "",
					},
				}
			case 8:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/dircolors",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/dircolors",
						Secondary: "",
					},
				}
			case 9:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/ls",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/ls",
						Secondary: "",
					},
				}
			case 10:
				extra = map[string]interface{}{
					"action": "executed",
					"how":    "/usr/bin/clear_console",
					"object": aucoalesce.Object{
						Type:      "file",
						Primary:   "/usr/bin/clear_console",
						Secondary: "",
					},
				}
			case 11:
				extra = map[string]interface{}{
					"action": "ended-session",
					"how":    "/usr/sbin/sshd",
					"object": aucoalesce.Object{
						Type:      "user-session",
						Primary:   "ssh",
						Secondary: "10.0.2.2",
					},
				}
			default:
				o.t.Fatalf("got unknown event index %d", i)
			}

			o.check(event, auditevent.EventMetadata{
				AuditID: auditdID,
				Extra:   extra,
			})

			if i == 11 {
				return
			}

			i++
		}
	}
}

func (o goodAuditdEventsChecker) check(target *auditevent.AuditEvent, meta auditevent.EventMetadata) {
	assert.NotNilf(o.t, o.login.Source, "remote user login audit event is nil")

	assert.Equal(o.t, common.ActionUserAction, target.Type)
	assert.Equal(o.t, auditevent.OutcomeSucceeded, target.Outcome)
	if target.LoggedAt.Equal(time.Time{}) {
		o.t.Fatal("logged at is equal to empty time.Time")
	}

	assert.Equal(o.t, "IP", o.login.Source.Source.Type)
	assert.Equal(o.t, "10.0.2.2", o.login.Source.Source.Value)
	assert.Equal(o.t, "666", o.login.Source.Source.Extra["port"])

	assert.Equal(o.t, o.login.Source.Subjects["userID"], target.Subjects["userID"])
	assert.Equal(o.t, o.login.Source.Subjects["loggedAs"], target.Subjects["loggedAs"])
	assert.Equal(o.t, o.login.Source.Subjects["pid"], target.Subjects["pid"])

	assert.Equal(o.t, o.login.Source.Target["host"], target.Target["host"])
	assert.Equal(o.t, o.login.Source.Target["machine-id"], target.Target["machine-id"])

	assert.Equal(o.t, meta.AuditID, target.Metadata.AuditID)

	if len(meta.Extra) == 0 {
		o.t.Fatalf("expacted-metadata's extra map is empty")
	}

	if len(target.Metadata.Extra) == 0 {
		o.t.Fatal("metadata's extra map is empty")
	}

	for kExp, vExp := range meta.Extra {
		something, hasIt := target.Metadata.Extra[kExp]
		if !hasIt {
			o.t.Fatalf("metadata is missing key '%s'", kExp)
		}

		assert.Equal(o.t, vExp, something, fmt.Sprintf("need value: '%v'", vExp))
	}
}
