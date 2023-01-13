package auditd

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

func TestNewSessionTracker(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	assert.NotNil(t, st.eventWriter)
	assert.NotNil(t, st.pidsToRULs)
	assert.NotNil(t, st.eventWriter)
}

func TestSessionTracker_RemoteLogin_ValidateErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	err := st.remoteLogin(common.RemoteUserLogin{
		Source:     nil,
		PID:        999,
		CredUserID: "foo",
	})

	var exp *common.RemoteUserLoginValidateError
	assert.ErrorAs(t, err, &exp)
}

func TestSessionTracker_RemoteLogin_HasAuditSession(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	expCache := make([]*aucoalesce.Event, intn(t, 0, 100))
	for i := range expCache {
		expCache[i] = newAucoalesceEvent(t, "123", "success", time.Now())
	}

	u := &user{
		added:  time.Now(),
		srcPID: 999,
		cached: make([]*aucoalesce.Event, len(expCache)),
	}

	copy(u.cached, expCache)

	events := make(chan *auditevent.AuditEvent, len(expCache))

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))

	st.sessIDsToUsers["123"] = u

	err := st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	for range expCache {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-events:
		}
	}
}

func TestSessionTracker_RemoteLogin_HasAuditSessionCache_WriteErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	u := &user{
		added:  time.Now(),
		srcPID: 999,
		cached: []*aucoalesce.Event{newAucoalesceEvent(t, "123", "failure", time.Now())},
	}

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	st.sessIDsToUsers["123"] = u

	cancelFn()

	err := st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})

	assert.ErrorIs(t, err, context.Canceled)
}

func TestSessionTracker_RemoteLogin_DoesNotHaveAuditSessionCache(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	expRUL := common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	}

	err := st.remoteLogin(expRUL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expRUL, st.pidsToRULs[expRUL.PID])
}

//nolint // Maybe the linter should read the documentation
func TestSessionTracker_AuditdEvent_NoSessionID(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	//nolint // Maybe the linter should read the documentation
	t.Run("EmptyString", func(t *testing.T) {
		err := st.auditdEvent(newAucoalesceEvent(t, "", "success", time.Now()))
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, st.sessIDsToUsers, 0)
	})

	//nolint // Maybe the linter should read the documentation
	t.Run("Unset", func(t *testing.T) {
		err := st.auditdEvent(newAucoalesceEvent(t, "unset", "success", time.Now()))
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, st.sessIDsToUsers, 0)
	})
}

func TestSessionTracker_AuditdEvent_ExistingSession_Ended(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numExtraEvents := 2
	numEventsToWrite := int(intn(t, 1, 100))
	events := make(chan *auditevent.AuditEvent, numEventsToWrite+numExtraEvents)

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.auditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	err = st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < numEventsToWrite-numExtraEvents; i++ {
		err = st.auditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))
		if err != nil {
			t.Fatal(err)
		}
	}

	endSessionEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	endSessionEvent.Type = auparse.AUDIT_CRED_DISP

	err = st.auditdEvent(endSessionEvent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, st.sessIDsToUsers, 0)
	assert.Len(t, st.pidsToRULs, 0)
	assert.Len(t, events, numEventsToWrite)
}

func TestSessionTracker_AuditdEvent_ExistingSession_NoRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numEventsToWrite := int(intn(t, 1, 100))

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	for i := 0; i < numEventsToWrite; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now())

		if i == 0 {
			event.Type = auparse.AUDIT_LOGIN
			event.Process.PID = "999"
		}

		err := st.auditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	assert.Len(t, st.sessIDsToUsers, 1)
	assert.Len(t, st.sessIDsToUsers["123"].cached, numEventsToWrite)
}

func TestSessionTracker_AuditdEvent_ExistingSession_WriteCacheErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numExtraEvents := 1
	numEventsToWrite := int(intn(t, 1, 100))
	events := make(chan *auditevent.AuditEvent, numEventsToWrite+numExtraEvents)

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.auditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	err = st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	// This is the only way to hit the code path we want
	// to test.
	u, hasIt := st.sessIDsToUsers["123"]
	if !hasIt {
		t.Fatal("sessIDsToUsers does not contain user for audit session id")
	}

	for i := 0; i < numEventsToWrite-numExtraEvents; i++ {
		u.cached = append(u.cached, newAucoalesceEvent(t, "123", "success", time.Now()))
	}

	cancelFn()

	err = st.auditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))

	assert.ErrorIs(t, err, context.Canceled)
}

func TestSessionTracker_AuditdEvent_ExistingSession_WriteErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	events := make(chan *auditevent.AuditEvent, 1)

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.auditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	err = st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	cancelFn()

	err = st.auditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))

	assert.ErrorIs(t, err, context.Canceled)
}

func TestSessionTracker_AuditdEvent_CreateSession_Skip(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_ANOM_CRYPTO_FAIL
	initialEvent.Process.PID = "999"

	err := st.auditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, st.sessIDsToUsers, 0)
}

func TestSessionTracker_AuditdEvent_CreateSession_BadPID(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "NaN"

	err := st.auditdEvent(initialEvent)

	var exp *strconv.NumError
	assert.ErrorAs(t, err, &exp)
}

func TestSessionTracker_AuditdEvent_CreateSession_WithRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent, 1),
		t:      t,
	}))

	err := st.remoteLogin(common.RemoteUserLogin{
		Source: &auditevent.AuditEvent{
			Subjects: map[string]string{
				"some key": "some value",
			},
			Source: auditevent.EventSource{
				Type:  "sshd",
				Value: "127.0.0.1",
			},
		},
		PID:        999,
		CredUserID: "foo",
	})
	if err != nil {
		t.Fatal(err)
	}

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err = st.auditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, st.pidsToRULs, 0)
	assert.Len(t, st.sessIDsToUsers, 1)
}

func TestSessionTracker_AuditdEvent_CreateSession_NoRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numEvents := int(intn(t, 1, 100))
	events := make(chan *auditevent.AuditEvent, numEvents)

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))

	for i := 0; i < numEvents; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now())
		event.Process.PID = "999"

		if i == 0 {
			event.Type = auparse.AUDIT_LOGIN
		}

		err := st.auditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	assert.Len(t, st.pidsToRULs, 0)
	assert.Len(t, st.sessIDsToUsers, 1)
	assert.Len(t, st.sessIDsToUsers["123"].cached, numEvents)
}

func TestSessionTracker_DeleteUsersWithoutLoginsBefore(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent, 1),
		t:      t,
	}))

	for i := 0; i < int(intn(t, 1, 100)); i++ {
		err := st.remoteLogin(common.RemoteUserLogin{
			Source: &auditevent.AuditEvent{
				LoggedAt: time.Now().Add(-time.Minute),
				Subjects: map[string]string{
					"some key": "some value",
				},
				Source: auditevent.EventSource{
					Type:  "sshd",
					Value: "127.0.0.1",
				},
			},
			PID:        int(intn(t, 2, 65535)),
			CredUserID: "foo",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	st.deleteRemoteUserLoginsBefore(time.Now())

	assert.Len(t, st.pidsToRULs, 0)
}

func TestSessionTracker_DeleteRemoteUserLoginsBefore(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numSessions := int(intn(t, 1, 100))
	st := newSessionTracker(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent, numSessions),
		t:      t,
	}))

	for i := 0; i < numSessions; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now().Add(-time.Minute))
		event.Type = auparse.AUDIT_LOGIN
		event.Process.PID = strconv.Itoa(int(intn(t, 2, 65535)))

		err := st.auditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	st.deleteUsersWithoutLoginsBefore(time.Now())

	assert.Len(t, st.sessIDsToUsers, 0)
}

func TestUser_ToAuditEvent(t *testing.T) {
	t.Parallel()

	u := user{
		added:  time.Now(),
		srcPID: 666,
		hasRUL: false,
		login: common.RemoteUserLogin{
			Source: &auditevent.AuditEvent{
				Subjects: map[string]string{
					"some key": "some value",
				},
				Source: auditevent.EventSource{
					Type:  "sshd",
					Value: "127.0.0.1",
				},
			},
		},
	}

	ae := &aucoalesce.Event{
		Result:    "success",
		Session:   "123",
		Timestamp: time.Now(),
		Summary: aucoalesce.Summary{
			Action: "foo",
			Object: aucoalesce.Object{
				Type:      "bar",
				Primary:   "1",
				Secondary: "2",
			},
			How: "how?",
		},
	}

	event := u.toAuditEvent(ae)

	assert.Equal(t, "auditd", event.Component)
	assert.Equal(t, event.Outcome, auditevent.OutcomeSucceeded)
	assert.Equal(t, ae.Timestamp, event.LoggedAt)
	assert.Equal(t, ae.Session, event.Metadata.AuditID)

	assert.Len(t, event.Metadata.Extra, 3)
	assert.Equal(t, ae.Summary.Action, event.Metadata.Extra["action"])
	assert.Equal(t, ae.Summary.How, event.Metadata.Extra["how"])
	assert.Equal(t, ae.Summary.Object, event.Metadata.Extra["object"])

	assert.Len(t, event.Subjects, len(u.login.Source.Subjects))
	for k, v := range u.login.Source.Subjects {
		x, hasIt := event.Subjects[k]
		if !hasIt {
			t.Fatalf("event.Metadata.Extra is missing key: '%s'", k)
		}

		assert.Equal(t, v, x)
	}
}

func TestUser_ToAuditEvent_Fail(t *testing.T) {
	t.Parallel()

	u := user{
		added:  time.Now(),
		srcPID: 666,
		hasRUL: false,
		login: common.RemoteUserLogin{
			Source: &auditevent.AuditEvent{
				Subjects: map[string]string{
					"some key": "some value",
				},
				Source: auditevent.EventSource{
					Type:  "sshd",
					Value: "127.0.0.1",
				},
			},
		},
	}

	ae := &aucoalesce.Event{
		Result:    "fail",
		Session:   "123",
		Timestamp: time.Now(),
		Summary: aucoalesce.Summary{
			Action: "foo",
			Object: aucoalesce.Object{
				Type:      "bar",
				Primary:   "1",
				Secondary: "2",
			},
			How: "31c066ba0e276681ea0627b037cd80",
		},
	}

	event := u.toAuditEvent(ae)

	assert.Equal(t, event.Outcome, auditevent.OutcomeFailed)
}

func TestUser_WriteAndClearCache(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	u := user{
		added:  time.Now(),
		srcPID: 666,
		hasRUL: false,
		login: common.RemoteUserLogin{
			Source: &auditevent.AuditEvent{
				Subjects: map[string]string{
					"sc": "01608fe216ff2fe178461030ff21ff310131082701df4040" +
						"012701df2f726f6f742f7077656364",
				},
				Source: auditevent.EventSource{
					Type:  "sshd",
					Value: "127.0.0.1",
				},
			},
		},
		cached: make([]*aucoalesce.Event, intn(t, 1, 100)),
	}

	for i := range u.cached {
		u.cached[i] = newAucoalesceEvent(t, "123", "success", time.Now())
	}

	numEvents := len(u.cached)

	events := make(chan *auditevent.AuditEvent, numEvents)

	err := u.writeAndClearCache(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: events,
		t:      t,
	}))
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, events, numEvents)

	assert.Len(t, u.cached, 0)
}

func TestUser_WriteAndClearCache_WriteErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	u := user{
		added:  time.Now(),
		srcPID: 666,
		hasRUL: false,
		login: common.RemoteUserLogin{
			Source: &auditevent.AuditEvent{
				Subjects: map[string]string{
					"f00dd00d": "6631c068090066b8ffffffff66506631c0b0256650cd80",
				},
				Source: auditevent.EventSource{
					Type:  "sshd",
					Value: "127.0.0.1",
				},
			},
		},
		cached: make([]*aucoalesce.Event, intn(t, 1, 100)),
	}

	for i := range u.cached {
		u.cached[i] = newAucoalesceEvent(t, "123", "success", time.Now())
	}

	numEvents := len(u.cached)

	cancelFn()

	err := u.writeAndClearCache(auditevent.NewAuditEventWriter(&testAuditEncoder{
		ctx:    ctx,
		events: make(chan *auditevent.AuditEvent),
		t:      t,
	}))

	assert.ErrorIs(t, err, context.Canceled)

	assert.Len(t, u.cached, numEvents)
}

func newAucoalesceEvent(t *testing.T, sessionID, outcome string, timestamp time.Time) *aucoalesce.Event {
	t.Helper()

	ae := &aucoalesce.Event{
		Result:    outcome,
		Session:   sessionID,
		Timestamp: timestamp,
		Summary: aucoalesce.Summary{
			Action: string(randomBytes(t, 1, 64)),
			Object: aucoalesce.Object{
				Type:      string(randomBytes(t, 1, 16)),
				Primary:   string(randomBytes(t, 1, 16)),
				Secondary: string(randomBytes(t, 1, 16)),
			},
			How: string(randomBytes(t, 1, 8)),
		},
	}

	return ae
}
