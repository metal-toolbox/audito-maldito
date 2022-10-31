package journald

import (
	"log"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

type testAuditEventEncoder struct {
	evt *auditevent.AuditEvent
	t   *testing.T
}

func (t *testAuditEventEncoder) Encode(rawevt any) error {
	var ok bool
	t.evt, ok = rawevt.(*auditevent.AuditEvent)
	assert.True(t.t, ok, "rawevt is not an *auditevent.AuditEvent")
	return nil
}

func compareAuditLogs(t *testing.T, want, got *auditevent.AuditEvent) {
	t.Helper()

	assert.Equal(t, want.Type, got.Type)
	assert.Equal(t, want.LoggedAt, got.LoggedAt)
	assert.Equal(t, want.Source.Type, got.Source.Type)
	assert.Equal(t, want.Source.Value, got.Source.Value)
	assert.Equal(t, want.Source.Extra, got.Source.Extra)
	assert.Equal(t, want.Outcome, got.Outcome)
	assert.Equal(t, want.Subjects, got.Subjects)
	assert.Equal(t, want.Target, got.Target)
}

func TestEntryProcessing(t *testing.T) {
	t.Parallel()

	expectedts, tserr := time.Parse(time.RFC3339, "2666-06-06T00:00:00Z")
	assert.NoError(t, tserr)

	type args struct {
		logentry string
		nodename string
		mid      string
		pid      string
	}
	tests := []struct {
		name string
		args args
		want *auditevent.AuditEvent
	}{
		{
			name: "Accept public key: Entry with CA and IPv4",
			args: args{
				//nolint:lll // This is a test case
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF ID satanic@panic.com (serial 1) CA ED25519 SHA256:ThisISACAChecksum+Right?",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "1234",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "127.0.0.1",
					Extra: map[string]any{
						"port": "666",
					},
				},
				Outcome: auditevent.OutcomeSucceeded,
				Subjects: map[string]string{
					"loggedAs": "core",
					"userID":   "satanic@panic.com",
					"pid":      "1234",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		// TODO(jaosorior): Add entry with IPv6
		{
			name: "Accept public key: Entry without CA",
			args: args{
				//nolint:lll // This is a test case
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "127.0.0.1",
					Extra: map[string]any{
						"port": "666",
					},
				},
				Outcome: auditevent.OutcomeSucceeded,
				Subjects: map[string]string{
					"loggedAs": "core",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "Accept public key: Entry without CA and padding data",
			args: args{
				//nolint:lll // This is a test case
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF and stuff",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "127.0.0.1",
					Extra: map[string]any{
						"port": "666",
					},
				},
				Outcome: auditevent.OutcomeSucceeded,
				Subjects: map[string]string{
					"loggedAs": "core",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "Invalid certificate: Entry with reason",
			args: args{
				logentry: "Certificate invalid: expired",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "unknown",
					Extra: map[string]any{
						"port": "unknown",
					},
				},
				Outcome: auditevent.OutcomeFailed,
				Subjects: map[string]string{
					"loggedAs": "unknown",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "User not in allowed list: root not allowed",
			args: args{
				logentry: "User root from 47.28.136.9 not allowed because not listed in AllowUsers",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "47.28.136.9",
				},
				Outcome: auditevent.OutcomeFailed,
				Subjects: map[string]string{
					"loggedAs": "root",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "User not in allowed list: root not allowed",
			args: args{
				logentry: "User walrus from 47.28.136.9 not allowed because not listed in AllowUsers",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "47.28.136.9",
				},
				Outcome: auditevent.OutcomeFailed,
				Subjects: map[string]string{
					"loggedAs": "walrus",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "Invalid user entry: Invalid user",
			args: args{
				logentry: "Invalid user cow from 47.8.6.9 port 64433",
				nodename: "testnode",
				mid:      "testmid",
				pid:      "666",
			},
			want: &auditevent.AuditEvent{
				Type:     common.ActionLoginIdentifier,
				LoggedAt: expectedts,
				Source: auditevent.EventSource{
					Type:  "IP",
					Value: "47.8.6.9",
					Extra: map[string]any{
						"port": "64433",
					},
				},
				Outcome: auditevent.OutcomeFailed,
				Subjects: map[string]string{
					"loggedAs": "cow",
					"userID":   common.UnknownUser,
					"pid":      "666",
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enc := &testAuditEventEncoder{t: t}
			w := auditevent.NewAuditEventWriter(enc)

			err := processEntry(&processEntryConfig{
				logEntry:  tt.args.logentry,
				nodeName:  tt.args.nodename,
				machineID: tt.args.mid,
				when:      expectedts,
				pid:       tt.args.pid,
				eventW:    w,
				logger:    log.Default(),
			})
			assert.NoError(t, err)

			compareAuditLogs(t, tt.want, enc.evt)

			// TODO(jaosorior): Add assertions for ExtraData
		})
	}
}
