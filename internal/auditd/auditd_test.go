package auditd

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func TestAuditd_Read_RemoveLoginError(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin, 1)
	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)

	a := Auditd{
		Audits: make(chan string),
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&testAuditEncoder{
			ctx:    ctx,
			events: events,
			t:      t,
		}),
	}

	errs := make(chan error, 1)
	go func() {
		errs <- a.Read(ctx)
	}()

	select {
	case err := <-errs:
		t.Fatal(err)
	case logins <- common.RemoteUserLogin{}:
	}

	err := <-errs

	var expErr *sessionTrackerError

	assert.ErrorAs(t, err, &expErr)

	if !expErr.remoteLoginFail {
		t.Fatal("expected remote login fail to be true - it is false")
	}
}

func TestAuditd_Read_ParseAuditLogError(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin)
	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)
	lines := make(chan string, 1)
	lines <- "foobar"

	a := Auditd{
		Audits: lines,
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&testAuditEncoder{
			ctx:    ctx,
			events: events,
			t:      t,
		}),
	}

	errs := make(chan error, 1)
	go func() {
		errs <- a.Read(ctx)
	}()

	err := <-errs

	var expErr *parseAuditLogsError

	assert.ErrorAs(t, err, &expErr)
}

func TestAuditd_Read_AuditEventError(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	lines, allowWritesFn, _ := newTestLogReader(ctx, []string{
		goodAuditd00,
		goodAuditd01,
		goodAuditd02,
		goodAuditd03,
		goodAuditd04,
		goodAuditd05,
	})

	logins := make(chan common.RemoteUserLogin, 1)
	logins <- newSshdJournaldAuditEvent("user", goodAuditdSshdPid)

	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)
	eventWCtx, cancelEventWFn := context.WithCancel(ctx)
	defer cancelEventWFn()

	a := Auditd{
		Audits: lines,
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&testAuditEncoder{
			ctx:    eventWCtx,
			events: events,
			t:      t,
		}),
	}

	cancelEventWFn()

	errs := make(chan error, 1)
	go func() {
		errs <- a.Read(ctx)
	}()

	allowWritesFn()

	err := <-errs

	var expErr *sessionTrackerError

	assert.ErrorAs(t, err, &expErr)

	if !expErr.auditEventFail {
		t.Fatal("expected audit event fail to be true - it is false")
	}
}

func TestMaintainReassemblerLoop_Cancel(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: make(chan reassembleAuditdEventResult),
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	cancelFn()

	maintainReassemblerLoop(ctx, reassembler, time.Second)
}

func TestMaintainReassemblerLoop_Maintain(t *testing.T) {
	t.Parallel()

	maintainDuration := time.Millisecond

	ctx, cancelFn := context.WithTimeout(context.Background(), 50*maintainDuration)
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: make(chan reassembleAuditdEventResult),
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	maintainReassemblerLoop(ctx, reassembler, time.Millisecond)
}

func TestMaintainReassemblerLoop_ReasemblerClosed(t *testing.T) {
	t.Parallel()

	maintainDuration := time.Millisecond

	ctx, cancelFn := context.WithTimeout(context.Background(), 50*maintainDuration)
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: make(chan reassembleAuditdEventResult),
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = reassembler.Close()

	maintainReassemblerLoop(ctx, reassembler, time.Millisecond)
}

func TestParseAuditLogs_Cancel(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult, 1)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	lines := make(chan string)

	cancelFn()

	err = parseAuditLogs(ctx, lines, reassembler)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseAuditLogs_EmptyAuditLine(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult, 1)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// An unbuffered channel is required here to ensure
	// the parseAuditLogs receives the empty string prior
	// to us executing cancelFn.
	lines := make(chan string)
	go func() {
		select {
		case <-ctx.Done():
			return
		case lines <- "":
			cancelFn()
		}
	}()

	err = parseAuditLogs(ctx, lines, reassembler)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseAuditLogs_LogParseFailure(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult, 1)

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}

	lines := make(chan string, 1)
	lines <- "foobar"

	err = parseAuditLogs(ctx, lines, reassembler)

	var expErr *parseAuditLogsError

	assert.ErrorAs(t, err, &expErr)
}

func TestReassemblerCB_ReassemblyComplete_Error(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult, 1)

	rcb := &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Time{},
	}

	rcb.ReassemblyComplete(nil)

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case r := <-results:
		var expErr *reassemblerCBError

		assert.ErrorAs(t, r.err, &expErr)
	}
}

func TestReassemblerCB_ReassemblyComplete_CancelOnError(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult)

	rcb := &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Time{},
	}

	cancelFn()

	rcb.ReassemblyComplete(nil)

	select {
	case <-results:
		t.Fatal("results chan should be empty because context was cancelled (it is non-empty)")
	default:
		// Good.
	}
}

func TestReassemblerCB_ReassemblyComplete_EventIsBefore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	results := make(chan reassembleAuditdEventResult, 1)

	rcb := &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Now(),
	}

	rcb.ReassemblyComplete([]*auparse.AuditMessage{
		{
			RecordType: auparse.AUDIT_LOGIN,
			Timestamp:  rcb.after.Add(-time.Minute),
		},
	})

	select {
	case <-results:
		t.Fatal("results chan should be empty because event occurred after filter (it is non-empty)")
	default:
		// Good.
	}
}

func TestReassemblerCB_ReassemblyComplete_CancelOnSend(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	results := make(chan reassembleAuditdEventResult)

	rcb := &reassemblerCB{
		ctx:     ctx,
		results: results,
		after:   time.Now(),
	}

	cancelFn()

	rcb.ReassemblyComplete([]*auparse.AuditMessage{
		{
			RecordType: auparse.AUDIT_LOGIN,
			Timestamp:  rcb.after.Add(time.Minute),
		},
	})

	select {
	case <-results:
		t.Fatal("results chan should be empty because event occurred after filter (it is non-empty)")
	default:
		// Good.
	}
}
