package auditd

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

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

	//nolint:dupl // The contents do not matter, why do I need to explain this?
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
		cached: []*aucoalesce.Event{
			{
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
			},
			{
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
					How: "01608fe216ff2fe178461030ff21ff310131082701df4040012701df2f726f6f742f7077656364",
				},
			},
			{
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
					How: "eb2b5e31c088460b88462950b0095031c05650b005cd8089c3" +
						"6a1d8d460c50535031c0b004cd8031c0b001cd80e8d0ffffff" +
						"2f746d702f706173737764307730307730303a3a303a303a77" +
						"30307730303a2f3a2f62696e2f73680a30ffffffffffffffff" +
						"ffffffffffffffffffffffff",
				},
			},
			{
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
					How: "0x6631c068090066b8ffffffff66506631c0b0256650cd80",
				},
			},
		},
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

	//nolint:dupl // The contents do not matter, why do I need to explain this?
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
		cached: []*aucoalesce.Event{
			{
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
					How: "f00dhow?",
				},
			},
			{
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
					How: "f00d01608fe216ff2fe178461030ff21ff310131082701df4040012701df2f726f6f742f7077656364",
				},
			},
			{
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
					How: "f00deb2b5e31c088460b88462950b0095031c05650b005cd8089c3" +
						"6a1d8d460c50535031c0b004cd8031c0b001cd80e8d0ffffff" +
						"2f746d702f706173737764307730307730303a3a303a303a77" +
						"30307730303a2f3a2f62696e2f73680a30ffffffffffffffff" +
						"ffffffffffffffffffffffff",
				},
			},
			{
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
					How: "f00d0x6631c068090066b8ffffffff66506631c0b0256650cd80",
				},
			},
		},
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
