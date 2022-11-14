package auditd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/auditevent"

	"go.uber.org/zap"
)

func TestMain(m *testing.M) {
	logger = zap.NewNop().Sugar()

	os.Exit(m.Run())
}

func TestAuditd_RemoteUserLoginFirst(t *testing.T) {
	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin)
	events := make(chan *auditevent.AuditEvent, 1)

	r, w := io.Pipe()
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	a := Auditd{
		Source: r,
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&auditEncoder{
			ctx:   ctx,
			event: events,
		}),
	}

	exited := make(chan error, 1)

	go func() {
		exited <- a.Read(ctx)
	}()

	select {
	case logins <- newSshdJournaldAuditEvent("user", auditdSshdPid):
	case err := <-exited:
		t.Fatalf("read exited unexpectedly while waiting for logins channel to accept write - %v", err)
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

		log.Println("TODO: login done")
		time.Sleep(3 * time.Second)

		_, err = w.Write([]byte(auditdExecLs))
		if err != nil {
			writesDone <- err
			return
		}

		log.Println("TODO: ls done")
		time.Sleep(3 * time.Second)

		_, err = w.Write([]byte(auditdLogout))
		if err != nil {
			writesDone <- err
			return
		}
	}()

	select {
	case <-ctx.Done():
		t.Fatalf("timed-out while waiting for auditd writes to finish - %s", ctx.Err())
	case err := <-writesDone:
		if err != nil {
			t.Fatalf("auditd writes failed - %s", err)
		}
	}

	select {
	case <-ctx.Done():
		t.Fatalf("timed-out while waiting for auditdevnet - %s", ctx.Err())
	case err := <-exited:
		t.Fatalf("read exited unexpectedly: %v", err)
	case event := <-events:
		log.Printf("%+v", event)
	}
}

type auditEncoder struct {
	ctx   context.Context
	event chan<- *auditevent.AuditEvent
}

func (o auditEncoder) Encode(i interface{}) error {
	event, ok := i.(*auditevent.AuditEvent)
	if !ok {
		return fmt.Errorf("failed to type assert event ('%T') as *auditevent.AuditEvent", i)
	}

	select {
	case o.event <- event:
		return nil
	case <-o.ctx.Done():
		return o.ctx.Err()
	}
}

func newSshdJournaldAuditEvent(unixAccountName string, pid int) common.RemoteUserLogin {
	evt := auditevent.NewAuditEvent(
		common.ActionLoginIdentifier,
		auditevent.EventSource{
			Type:  "IP",
			Value: "127.0.0.1",
			Extra: map[string]any{
				"port": "666",
			},
		},
		auditevent.OutcomeSucceeded,
		map[string]string{
			"loggedAs": unixAccountName,
			"pid":      strconv.Itoa(pid),
		},
		"sshd",
	).WithTarget(map[string]string{
		"host":       "localhost",
		"machine-id": "foobar",
	})

	usernameFromCert := "x"
	evt.LoggedAt = time.Now()
	evt.Subjects["userID"] = usernameFromCert

	return common.RemoteUserLogin{
		Source:     evt,
		PID:        pid,
		CredUserID: usernameFromCert,
	}
}
