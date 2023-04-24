package sessiontracker

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

func TestNewSessionTracker(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	assert.NotNil(t, st.eventWriter)
	assert.NotNil(t, st.pidsToRULs)
	assert.NotNil(t, st.eventWriter)
}

func TestSessionTracker_RemoteLogin_ValidateErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	err := st.RemoteLogin(common.RemoteUserLogin{
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

	expCache := make([]*aucoalesce.Event, testtools.Intn(t, 0, 100))
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

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
	}), nil)

	st.sessIDsToUsers.Store("123", u)

	err := st.RemoteLogin(common.RemoteUserLogin{
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

	expErr := errors.New("write error")

	eventEncoder := &testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
		Err:    expErr,
	}

	st := NewSessionTracker(auditevent.NewAuditEventWriter(eventEncoder), nil)

	st.sessIDsToUsers.Store("123", u)

	err := st.RemoteLogin(common.RemoteUserLogin{
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

	assert.ErrorIs(t, err, expErr)
}

func TestSessionTracker_RemoteLogin_DoesNotHaveAuditSessionCache(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

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

	err := st.RemoteLogin(expRUL)
	if err != nil {
		t.Fatal(err)
	}

	observedLogin, found := st.pidsToRULs.Load(expRUL.PID)
	assert.True(t, found, "expected to find remote user login in pidsToRULs")
	assert.Equal(t, expRUL, observedLogin)
}

func TestSessionTracker_AuditdEvent_NoSessionID(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancelFn)

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	t.Run("EmptyString", func(t *testing.T) {
		t.Parallel()

		err := st.AuditdEvent(newAucoalesceEvent(t, "", "success", time.Now()))
		require.NoError(t, err, "expected no error when session ID is empty string")

		assert.Equal(t, st.sessIDsToUsers.Len(), 0)
	})

	t.Run("Unset", func(t *testing.T) {
		t.Parallel()

		err := st.AuditdEvent(newAucoalesceEvent(t, "unset", "success", time.Now()))
		require.NoError(t, err, "expected no error when session ID is unset")

		assert.Equal(t, st.sessIDsToUsers.Len(), 0)
	})
}

// TestSessionTracker_AuditdEvent_ExistingSession_Ended verifies
// that a session is removed from the session tracker when the
// session ends. In this case, the session comes from an audit event,
// creating a mapping in the sessIDsToUsers map; However, at no point
// is the session added to the pidsToRULs map.
func TestSessionTracker_AuditdEvent_ExistingSession_Ended(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	// "Extra events": Meaning events created outside the loop below.
	// These events (such as login / logout) are needed for a session
	// to be created.
	//
	// Note: The number of "extra" events must be less than the
	// minimum number of generated events to prevent arithmetic
	// errors in the for loop condition (e.g., if extra events
	// is 1 and the number of generated events is 2:
	//
	//	1-2 = -1
	//
	// As a result, the code contained in the loop will not execute.
	numExtraEvents := 2
	numEventsToWrite := int(testtools.Intn(t, int64(numExtraEvents+1), 100))
	events := make(chan *auditevent.AuditEvent, numEventsToWrite+numExtraEvents)

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
	}), nil)

	// Create a session with a login event.
	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.AuditdEvent(initialEvent)
	require.NoError(t, err, "failed to write initial event")

	t.Logf("We have an initial event. The session tracker should have 1 session and 0 PID")
	require.Equal(t, 1, st.sessIDsToUsers.Len(), "expected 1 session")
	require.Equal(t, 0, st.pidsToRULs.Len(), "expected 0 PID")

	err = st.RemoteLogin(common.RemoteUserLogin{
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
	require.NoError(t, err, "failed to register remote login event")

	t.Logf("We caught a remote login. " +
		"The session tracker should have 1 session and 0 PID since there is already an audit session " +
		"for this login")
	require.Equal(t, 1, st.sessIDsToUsers.Len(), "expected 1 session")
	require.Equal(t, 0, st.pidsToRULs.Len(), "expected 0 PID")

	t.Logf("We will write %d events", numEventsToWrite)
	for i := 0; i < numEventsToWrite-numExtraEvents; i++ {
		err = st.AuditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))
		require.NoError(t, err, "failed to write event")

		require.Equal(t, 1, st.sessIDsToUsers.Len(), "expected 1 session")
		require.Equal(t, 0, st.pidsToRULs.Len(), "expected 0 PID")
	}

	endSessionEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	endSessionEvent.Type = auparse.AUDIT_CRED_DISP

	err = st.AuditdEvent(endSessionEvent)
	require.NoError(t, err, "failed to write end session event")

	assert.Equal(t, st.sessIDsToUsers.Len(), 0)
	assert.Equal(t, st.pidsToRULs.Len(), 0)
	assert.Len(t, events, numEventsToWrite)
}

func TestSessionTracker_AuditdEvent_ExistingSession_NoRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numEventsToWrite := int(testtools.Intn(t, 1, 100))

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	for i := 0; i < numEventsToWrite; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now())

		if i == 0 {
			event.Type = auparse.AUDIT_LOGIN
			event.Process.PID = "999"
		}

		err := st.AuditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	assert.Equal(t, st.sessIDsToUsers.Len(), 1)
	cachedSess, found := st.sessIDsToUsers.Load("123")
	assert.True(t, found)
	assert.Len(t, cachedSess.cached, numEventsToWrite)
}

func TestSessionTracker_AuditdEvent_ExistingSession_WriteCacheErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	// "Extra events": Meaning events created outside the loop below.
	// These events (such as login / logout) are needed for a session
	// to be created.
	//
	// Note: The number of "extra" events must be less than the
	// minimum number of generated events to prevent arithmetic
	// errors in the for loop condition (e.g., if extra events
	// is 1 and the number of generated events is 2:
	//
	//	1-2 = -1
	//
	// As a result, the code contained in the loop will not execute.
	numExtraEvents := 1
	numEventsToWrite := int(testtools.Intn(t, int64(numExtraEvents+1), 100))
	events := make(chan *auditevent.AuditEvent, numEventsToWrite+numExtraEvents)

	eventEncoder := &testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
	}

	st := NewSessionTracker(auditevent.NewAuditEventWriter(eventEncoder), nil)

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.AuditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	err = st.RemoteLogin(common.RemoteUserLogin{
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
	u, hasIt := st.sessIDsToUsers.Load("123")
	if !hasIt {
		t.Fatal("sessIDsToUsers does not contain user for audit session id")
	}

	for i := 0; i < numEventsToWrite-numExtraEvents; i++ {
		u.cached = append(u.cached, newAucoalesceEvent(t, "123", "success", time.Now()))
	}

	expErr := errors.New("write error")

	eventEncoder.Err = expErr

	err = st.AuditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))

	assert.ErrorIs(t, err, expErr)
}

func TestSessionTracker_AuditdEvent_ExistingSession_WriteErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	events := make(chan *auditevent.AuditEvent, 1)

	eventEncoder := &testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
	}

	st := NewSessionTracker(auditevent.NewAuditEventWriter(eventEncoder), nil)

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "999"

	err := st.AuditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	err = st.RemoteLogin(common.RemoteUserLogin{
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

	expErr := errors.New("write error")
	eventEncoder.Err = expErr

	err = st.AuditdEvent(newAucoalesceEvent(t, "123", "success", time.Now()))

	assert.ErrorIs(t, err, expErr)
}

func TestSessionTracker_AuditdEvent_CreateSession_Skip(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_ANOM_CRYPTO_FAIL
	initialEvent.Process.PID = "999"

	err := st.AuditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, st.sessIDsToUsers.Len(), 0)
}

func TestSessionTracker_AuditdEvent_CreateSession_BadPID(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
	}), nil)

	initialEvent := newAucoalesceEvent(t, "123", "success", time.Now())
	initialEvent.Type = auparse.AUDIT_LOGIN
	initialEvent.Process.PID = "NaN"

	err := st.AuditdEvent(initialEvent)

	var exp *strconv.NumError
	assert.ErrorAs(t, err, &exp)
}

func TestSessionTracker_AuditdEvent_CreateSession_WithRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent, 1),
		T:      t,
	}), nil)

	err := st.RemoteLogin(common.RemoteUserLogin{
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

	err = st.AuditdEvent(initialEvent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, st.pidsToRULs.Len(), 0)
	assert.Equal(t, st.sessIDsToUsers.Len(), 1)
}

func TestSessionTracker_AuditdEvent_CreateSession_NoRUL(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numEvents := int(testtools.Intn(t, 1, 100))
	events := make(chan *auditevent.AuditEvent, numEvents)

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
	}), nil)

	for i := 0; i < numEvents; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now())
		event.Process.PID = "999"

		if i == 0 {
			event.Type = auparse.AUDIT_LOGIN
		}

		err := st.AuditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	assert.Equal(t, st.pidsToRULs.Len(), 0)
	assert.Equal(t, st.sessIDsToUsers.Len(), 1)
	cachedsess, found := st.sessIDsToUsers.Load("123")
	assert.True(t, found)
	assert.Len(t, cachedsess.cached, numEvents)
}

func TestSessionTracker_DeleteRemoteUserLoginsBefore(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent, 1),
		T:      t,
	}), nil)

	for i := 0; i < int(testtools.Intn(t, 1, 100)); i++ {
		err := st.RemoteLogin(common.RemoteUserLogin{
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
			PID:        int(testtools.Intn(t, 2, 65535)),
			CredUserID: "foo",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	st.DeleteRemoteUserLoginsBefore(time.Now())

	assert.Equal(t, st.pidsToRULs.Len(), 0)
}

func TestSessionTracker_DeleteUsersWithoutLoginsBefore(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	numSessions := int(testtools.Intn(t, 1, 100))
	st := NewSessionTracker(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent, numSessions),
		T:      t,
	}), nil)

	for i := 0; i < numSessions; i++ {
		event := newAucoalesceEvent(t, "123", "success", time.Now().Add(-time.Minute))
		event.Type = auparse.AUDIT_LOGIN
		event.Process.PID = strconv.Itoa(int(testtools.Intn(t, 2, 65535)))

		err := st.AuditdEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}

	st.DeleteUsersWithoutLoginsBefore(time.Now())

	assert.Equal(t, st.sessIDsToUsers.Len(), 0)
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
		Process: aucoalesce.Process{
			Args: []string{"foo", "bar"},
		},
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

	assert.Len(t, event.Metadata.Extra, 4)
	assert.Equal(t, ae.Summary.Action, event.Metadata.Extra["action"])
	assert.Equal(t, ae.Summary.How, event.Metadata.Extra["how"])
	assert.Equal(t, ae.Summary.Object, event.Metadata.Extra["object"])
	assert.NotNil(t, event.Metadata.Extra["object"])
	assert.Equal(t, ae.Process.Args, event.Metadata.Extra["process_args"])
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
		Process: aucoalesce.Process{
			Args: nil,
		},
	}

	event := u.toAuditEvent(ae)
	assert.Nil(t, event.Metadata.Extra["process_args"])
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
		cached: make([]*aucoalesce.Event, testtools.Intn(t, 1, 100)),
	}

	for i := range u.cached {
		u.cached[i] = newAucoalesceEvent(t, "123", "success", time.Now())
	}

	numEvents := len(u.cached)

	events := make(chan *auditevent.AuditEvent, numEvents)

	err := u.writeAndClearCache(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: events,
		T:      t,
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
		cached: make([]*aucoalesce.Event, testtools.Intn(t, 1, 100)),
	}

	for i := range u.cached {
		u.cached[i] = newAucoalesceEvent(t, "123", "success", time.Now())
	}

	numEvents := len(u.cached)

	expErr := errors.New("write error")

	err := u.writeAndClearCache(auditevent.NewAuditEventWriter(&testtools.TestAuditEncoder{
		Ctx:    ctx,
		Events: make(chan *auditevent.AuditEvent),
		T:      t,
		Err:    expErr,
	}))

	assert.ErrorIs(t, err, expErr)

	assert.Len(t, u.cached, numEvents)
}

func newAucoalesceEvent(t *testing.T, sessionID, outcome string, timestamp time.Time) *aucoalesce.Event {
	t.Helper()

	ae := &aucoalesce.Event{
		Result:    outcome,
		Session:   sessionID,
		Timestamp: timestamp,
		Summary: aucoalesce.Summary{
			Action: string(testtools.RandomBytes(t, 1, 64)),
			Object: aucoalesce.Object{
				Type:      string(testtools.RandomBytes(t, 1, 16)),
				Primary:   string(testtools.RandomBytes(t, 1, 16)),
				Secondary: string(testtools.RandomBytes(t, 1, 16)),
			},
			How: string(testtools.RandomBytes(t, 1, 8)),
		},
	}

	return ae
}
