package auditd

//go:generate go run gen-extra-map/main.go -only-ids -d Good -o auditd_good_metadata_test.go testdata/good

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

const (
	goodAuditdID = "499"

	goodAuditdMaxResultingEvents = 300

	goodAuditdSshdPid = 25007
)

var (
	//go:embed testdata/good/00-login.txt
	goodAuditd00 string

	//go:embed testdata/good/01-ls-cwd.txt
	goodAuditd01 string

	//go:embed testdata/good/02-cat-resolv-conf.txt
	goodAuditd02 string

	//go:embed testdata/good/03-ls-slash-root.txt
	goodAuditd03 string

	//go:embed testdata/good/04-logout.txt
	goodAuditd04 string

	//go:embed testdata/good/05-unrelated.txt
	goodAuditd05 string
)

func TestMain(m *testing.M) {
	logger = zap.NewNop().Sugar()

	os.Exit(m.Run())
}

func TestAuditd_Read_GoodRemoteUserLoginFirst(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin)
	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)

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
			t:      t,
		}),
	}

	exited := make(chan error, 1)

	go func() {
		exited <- a.Read(ctx)
	}()

	sshLogin := newSshdJournaldAuditEvent("user", goodAuditdSshdPid)

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
		_, err := w.Write([]byte(goodAuditd00))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd01))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd02))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd03))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd04))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd05))
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

	goodChecker := goodAuditdEventsChecker{
		login:  sshLogin,
		events: events,
		exited: exited,
		t:      t,
	}

	goodChecker.check()
}

func TestAuditd_Read_GoodAuditdEventsFirst(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin)
	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)

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
			t:      t,
		}),
	}

	exited := make(chan error, 1)

	go func() {
		exited <- a.Read(ctx)
	}()

	writesDone := make(chan error, 1)
	go func() {
		// Perform writes in a separate Go routine in order to
		// handle potential scenarios where the writes block.
		// This allows the context to timeout and the test
		// to fail.
		_, err := w.Write([]byte(goodAuditd00))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd01))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd02))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd03))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd04))
		if err != nil {
			writesDone <- err
			return
		}

		_, err = w.Write([]byte(goodAuditd05))
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

	sshLogin := newSshdJournaldAuditEvent("user", goodAuditdSshdPid)

	select {
	case logins <- sshLogin:
	case err := <-exited:
		t.Fatalf("read exited unexpectedly while writing remote user login to logins chan - %v", err)
	}

	checker := goodAuditdEventsChecker{
		login:  sshLogin,
		events: events,
		exited: exited,
		t:      t,
	}

	checker.check()
}

type testAuditEncoder struct {
	ctx    context.Context //nolint
	events chan<- *auditevent.AuditEvent
	t      *testing.T
}

func (o testAuditEncoder) Encode(i interface{}) error {
	event, ok := i.(*auditevent.AuditEvent)
	if !ok {
		o.t.Fatalf("failed to type assert event ('%T') as *auditevent.AuditEvent", i)
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
	usernameFromCert := "foo@bar.com"

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

// goodAuditdEventsChecker verifies events generated by an Auditd object
// match the "good" auditd events test data.
type goodAuditdEventsChecker struct {
	// login is the original common.RemoteUserLogin that is
	// associated with the auditd events.
	login common.RemoteUserLogin

	// events is the channel from which auditevent.AuditEvent
	// are read from.
	events <-chan *auditevent.AuditEvent

	// exited is the channel from which a nil or non-nil error
	// is read from when the Auditd.Read method returns.
	exited <-chan error

	// t is the current testing.T.
	t *testing.T
}

// check reads auditevent.AuditEvent from the events channel and verifies
// that they match the expected output using the checkEvent method.
//
// It also monitors the exited channel and fails the current test if
// any writes occur.
func (o goodAuditdEventsChecker) check() {
	i := 0

	for {
		select {
		case err := <-o.exited:
			o.t.Fatalf("read exited unexpectedly - %v", err)
		case event := <-o.events:
			if i > 200 && event.Metadata.Extra["action"] == "disposed-credentials" {
				return
			}

			o.checkEvent(i, event, auditevent.EventMetadata{
				AuditID: goodAuditdID,
				Extra:   metadataForGoodAuditdEvents(i, o.t),
			})

			i++
		}
	}
}

// checkEvent verifies that the target auditevent.AuditEvent contains
// the fields from the original common.RemoteUserLogin stored in
// the goodAuditdEventsChecker.
func (o goodAuditdEventsChecker) checkEvent(i int, target *auditevent.AuditEvent, meta auditevent.EventMetadata) {
	assert.NotNilf(o.t, o.login.Source, "i: %d | remote user login audit event is nil", i)
	assert.Equal(o.t, common.ActionUserAction, target.Type, "i: %d", i)

	var expResult string
	switch i {
	case 0, 4, 5, 6, 19, 20, 21, 24, 25, 26, 147, 149, 150:
		expResult = auditevent.OutcomeFailed
	default:
		expResult = auditevent.OutcomeSucceeded
	}

	assert.Equal(o.t, expResult, target.Outcome, "i: %d", i)

	if target.LoggedAt.Equal(time.Time{}) {
		o.t.Fatalf("i: %d | logged at is equal to empty time.Time", i)
	}

	assert.Equal(o.t, "IP", o.login.Source.Source.Type, "i: %d", i)
	assert.Equal(o.t, "127.0.0.1", o.login.Source.Source.Value, "i: %d", i)
	assert.Equal(o.t, "666", o.login.Source.Source.Extra["port"], "i: %d", i)

	assert.Equal(o.t, o.login.Source.Subjects["userID"], target.Subjects["userID"], "i: %d", i)
	assert.Equal(o.t, o.login.Source.Subjects["loggedAs"], target.Subjects["loggedAs"], "i: %d", i)
	assert.Equal(o.t, o.login.Source.Subjects["pid"], target.Subjects["pid"], "i: %d", i)

	assert.Equal(o.t, o.login.Source.Target["host"], target.Target["host"], "i: %d", i)
	assert.Equal(o.t, o.login.Source.Target["machine-id"], target.Target["machine-id"], "i: %d", i)

	assert.Equal(o.t, meta.AuditID, target.Metadata.AuditID, "i: %d", i)

	if len(meta.Extra) == 0 {
		o.t.Fatalf("i: %d | expacted-metadata's extra map is empty", i)
	}

	if len(target.Metadata.Extra) == 0 {
		o.t.Fatalf("i: %d | metadata's extra map is empty", i)
	}

	for kExp, vExp := range meta.Extra { //nolint
		something, hasIt := target.Metadata.Extra[kExp]
		if !hasIt {
			o.t.Fatalf("i: %d | metadata is missing key '%s'", i, kExp)
		}

		assert.Equal(o.t, vExp, something, fmt.Sprintf("i: %d | need value: '%v'", i, vExp))
	}
}
