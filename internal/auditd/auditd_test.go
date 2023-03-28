package auditd

import (
	"bufio"
	"context"
	_ "embed"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/metal-toolbox/audito-maldito/internal/auditd/sessiontracker"
	fakest "github.com/metal-toolbox/audito-maldito/internal/auditd/sessiontracker/fakes"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

func TestAuditd_Read_RemoteLoginError(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	logins := make(chan common.RemoteUserLogin, 1)
	events := make(chan *auditevent.AuditEvent, goodAuditdMaxResultingEvents)

	a := Auditd{
		Audits: make(chan string),
		Logins: logins,
		EventW: auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
			Ctx:    ctx,
			Events: events,
			T:      t,
		}),
		Health: health.NewSingleReadinessHealth(AuditdProcessorComponentName),
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

	var expErr *sessiontracker.SessionTrackerError

	assert.ErrorAs(t, err, &expErr)

	if !expErr.RemoteLoginFailed() {
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
		EventW: auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
			Ctx:    ctx,
			Events: events,
			T:      t,
		}),
		Health: health.NewSingleReadinessHealth(AuditdProcessorComponentName),
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
		EventW: auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
			Ctx:    eventWCtx,
			Events: events,
			T:      t,
		}),
		Health: health.NewSingleReadinessHealth(AuditdProcessorComponentName),
	}

	cancelEventWFn()

	errs := make(chan error, 1)
	go func() {
		errs <- a.Read(ctx)
	}()

	allowWritesFn()

	err := <-errs

	var expErr *sessiontracker.SessionTrackerError

	assert.ErrorAs(t, err, &expErr)

	if !expErr.AuditEventFailed() {
		t.Fatal("expected audit event fail to be true - it is false")
	}
}

func TestMaintainReassemblerLoop_Cancel(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

	cancelFn()

	maintainReassemblerLoop(ctx, reassembler, time.Second)
}

func TestMaintainReassemblerLoop_Maintain(t *testing.T) {
	t.Parallel()

	maintainDuration := time.Millisecond

	ctx, cancelFn := context.WithTimeout(context.Background(), 50*maintainDuration)
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

	maintainReassemblerLoop(ctx, reassembler, time.Millisecond)
}

func TestMaintainReassemblerLoop_ReasemblerClosed(t *testing.T) {
	t.Parallel()

	maintainDuration := time.Millisecond

	ctx, cancelFn := context.WithTimeout(context.Background(), 50*maintainDuration)
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

	_ = reassembler.Close()

	maintainReassemblerLoop(ctx, reassembler, time.Millisecond)
}

func TestParseAuditLogs_Cancel(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

	lines := make(chan string)

	cancelFn()

	err = parseAuditLogs(ctx, lines, reassembler)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseAuditLogs_EmptyAuditLine(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

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

	reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	require.NoError(t, err, "failed to create reassembler")

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

	rcbErrs := make(chan error, 1)
	rcb := &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: rcbErrs,
		after:  time.Time{},
	}

	rcb.ReassemblyComplete(nil)

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case r := <-rcbErrs:
		var expErr *reassemblerCBError

		assert.ErrorAs(t, r, &expErr)
	}
}

func TestReassemblerCB_ReassemblyComplete_EventIsBefore(t *testing.T) {
	t.Parallel()

	rcbErrs := make(chan error, 1)
	rcb := &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			return nil
		}),
		errors: rcbErrs,
		after:  time.Now(),
	}

	rcb.ReassemblyComplete([]*auparse.AuditMessage{
		{
			RecordType: auparse.AUDIT_LOGIN,
			Timestamp:  rcb.after.Add(-time.Minute),
		},
	})

	require.Empty(t, rcbErrs, "errors chan should be empty because event occurred before filter")
}

// Refer to the following GitHub issue for details:
// https://github.com/elastic/go-libaudit/issues/127
//
//nolint:paralleltest,tparallel // All tests being parallel results in early exit.
func TestReassemblerCB_CompoundEventsMissingSyscall(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	//nolint // this is
	const case0 = `type=AVC msg=audit(1668179838.476:649407): avc:  denied  { search } for  pid=4059486 comm="cephcsi" name="crypto" dev="proc" ino=475090959 scontext=system_u:system_r:svirt_lxc_net_t:s0:c222,c955 tcontext=system_u:object_r:sysctl_crypto_t:s0 tclass=dir permissive=1
type=AVC msg=audit(1668179838.476:649407): avc:  denied  { read } for  pid=4059486 comm="cephcsi" name="fips_enabled" dev="proc" ino=475090960 scontext=system_u:system_r:svirt_lxc_net_t:s0:c222,c955 tcontext=system_u:object_r:sysctl_crypto_t:s0 tclass=file permissive=1
type=AVC msg=audit(1668179838.476:649407): avc:  denied  { open } for  pid=4059486 comm="cephcsi" path="/proc/sys/crypto/fips_enabled" dev="proc" ino=475090960 scontext=system_u:system_r:svirt_lxc_net_t:s0:c222,c955 tcontext=system_u:object_r:sysctl_crypto_t:s0 tclass=file permissive=1
`
	//nolint // the way
	const case1 = `type=EXECVE msg=audit(1671230062.742:657491): argc=2 a0="uname" a1="-p"
type=CWD msg=audit(1671230062.742:657491): cwd="/root"
type=PATH msg=audit(1671230062.742:657491): item=0 name="/usr/bin/uname" inode=76040 dev=fe:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:unlabeled_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1671230062.742:657491): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=98548 dev=fe:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:unlabeled_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1671230062.742:657491): proctitle=756E616D65002D70
`

	//nolint // I want it to be
	const case2 = `type=EXECVE msg=audit(1671230063.745:657579): argc=3 a0="/usr/sbin/ethtool" a1="-T" a2="lxc61be96845005"
type=CWD msg=audit(1671230063.745:657579): cwd="/root"
type=PATH msg=audit(1671230063.745:657579): item=0 name="/usr/sbin/ethtool" inode=162594 dev=fe:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:unlabeled_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1671230063.745:657579): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=98548 dev=fe:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:unlabeled_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1671230063.745:657579): proctitle=2F7573722F7362696E2F657468746F6F6C002D54006C7863363162653936383435303035
`

	cases := []string{case0, case1, case2}

	assert.NotEmpty(t, cases)

	for i, messageLinesSet := range cases {
		//nolint:paralleltest // All tests being parallel results in early exit.
		t.Run("TestCase"+strconv.Itoa(i), func(t *testing.T) {
			rcbErrors := make(chan error, 1)
			called := false

			reassembler, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
				au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
					called = true
					return nil
				}),
				errors: rcbErrors,
				after:  time.Time{},
			})
			if err != nil {
				t.Fatalf("failed to create resassembler - %s", err)
			}
			defer reassembler.Close()

			scanner := bufio.NewScanner(strings.NewReader(messageLinesSet))

			for scanner.Scan() {
				message, err := auparse.ParseLogLine(scanner.Text())
				if err != nil {
					t.Fatalf("parse log line failed for case %d - %s", i, err)
				}

				x := make(chan struct{})
				go func() {
					reassembler.PushMessage(message)
					close(x)
				}()

				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-x:
				}
			}

			// Force event to be spat out.
			_ = reassembler.Close()

			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case err := <-rcbErrors:
				if err != nil {
					t.Fatalf("got non-nil error for case %d - %s", i, err)
				}
			default:
				require.True(t, called, "reassembler callback was not called for case %d", i)
			}
		})
	}
}

//go:embed testdata/good/03-ls-slash-root.txt
var reassemblerCloseTestEvents string

func TestReassemblerCloseFlushesEvents(t *testing.T) {
	t.Parallel()

	// Split the events into 1 chunks.
	nEvents := 3
	loginEvents := []string{goodAuditd00}
	eventSlice := strings.Split(reassemblerCloseTestEvents, "\n")[:nEvents]

	ctx, cancelFn := context.WithCancel(context.Background())

	lines, allowWritesFn, writesDone := newTestLogReader(ctx,
		append(loginEvents, eventSlice...))

	var aucounter atomic.Int32

	// create reassembler
	reas, err := libaudit.NewReassembler(maxEventsInFlight, eventTimeout, &reassemblerCB{
		au: fakest.NewFakeAuditor(func(event *aucoalesce.Event) error {
			aucounter.Add(1)
			return nil
		}),
		errors: make(chan error, 1),
		after:  time.Time{},
	})
	assert.NoError(t, err, "failed to create reassembler")

	// create session tracker
	wg := sync.WaitGroup{}

	allowWritesFn()

	wg.Add(1)

	// This consumes the raw events and pushes them into the reassembler.
	// this is similar to the auditd Read function go routine which calls
	// this the `parseAuditLogs` function.
	// It will stop listening once the context is cancelled.
	go func() {
		defer wg.Done()

		err := parseAuditLogs(ctx, lines, reas)
		assert.ErrorIs(t, err, context.Canceled, "expected context to be cancelled")
	}()

	<-writesDone

	// Cancel reading events before we close
	cancelFn()

	wg.Wait()

	eventsBeforeClose := int(aucounter.Load())

	// Close the reassembler
	reas.Close()

	eventsAfterClose := int(aucounter.Load())

	diff := eventsAfterClose - eventsBeforeClose

	// Check that the reassembler flushed all events.
	// The number of coalesced events is simply 1 as it aggregates the audit
	// events and assembles it with all the info it can get.
	assert.Equal(t, 1, diff, "expected 1 events to be flushed")
}
