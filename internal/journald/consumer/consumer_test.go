package consumer

import (
	"testing"

	"github.com/metal-toolbox/auditevent"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/stretchr/testify/assert"
)

type testAuditEventEncoder struct {
	evt *auditevent.AuditEvent
}

func (t *testAuditEventEncoder) Encode(rawevt any) error {
	t.evt = rawevt.(*auditevent.AuditEvent)
	return nil
}

func Test_processAcceptPublicKeyEntry(t *testing.T) {
	type args struct {
		logentry string
		nodename string
		mid      string
	}
	tests := []struct {
		name string
		args args
		want *auditevent.AuditEvent
	}{
		{
			name: "Entry with CA and IPv4",
			args: args{
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF ID satanic@panic.com (serial 1) CA ED25519 SHA256:ThisISACAChecksum+Right?",
				nodename: "testnode",
				mid:      "testmid",
			},
			want: &auditevent.AuditEvent{
				Type: common.ActionLoginIdentifier,
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
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		// TODO(jaosorior): Add entry with IPv6
		{
			name: "Entry without CA",
			args: args{
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF",
				nodename: "testnode",
				mid:      "testmid",
			},
			want: &auditevent.AuditEvent{
				Type: common.ActionLoginIdentifier,
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
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
		{
			name: "Entry without CA and padding data",
			args: args{
				logentry: "Accepted publickey for core from 127.0.0.1 port 666 ssh2: ED25519-CERT SHA256:qM6MXh9sUr+*****+IAML33tDEADBEEF and stuff",
				nodename: "testnode",
				mid:      "testmid",
			},
			want: &auditevent.AuditEvent{
				Type: common.ActionLoginIdentifier,
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
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := &testAuditEventEncoder{}
			w := auditevent.NewAuditEventWriter(enc)
			processAcceptPublicKeyEntry(tt.args.logentry, tt.args.nodename, tt.args.mid, w)

			assert.Equal(t, tt.want.Type, enc.evt.Type)
			assert.Equal(t, tt.want.Source.Type, enc.evt.Source.Type)
			assert.Equal(t, tt.want.Source.Value, enc.evt.Source.Value)
			assert.Equal(t, tt.want.Source.Extra, enc.evt.Source.Extra)
			assert.Equal(t, tt.want.Outcome, enc.evt.Outcome)
			assert.Equal(t, tt.want.Subjects, enc.evt.Subjects)
			assert.Equal(t, tt.want.Target, enc.evt.Target)

			// TODO(jaosorior): Add assertions for ExtraData
		})
	}
}

func Test_processCertificateInvalidEntry(t *testing.T) {
	type args struct {
		logentry string
		nodename string
		mid      string
	}
	tests := []struct {
		name string
		args args
		want *auditevent.AuditEvent
	}{
		{
			name: "Entry with reason",
			args: args{
				logentry: "Certificate invalid: expired",
				nodename: "testnode",
				mid:      "testmid",
			},
			want: &auditevent.AuditEvent{
				Type: common.ActionLoginIdentifier,
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
				},
				Target: map[string]string{
					"host":       "testnode",
					"machine-id": "testmid",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := &testAuditEventEncoder{}
			w := auditevent.NewAuditEventWriter(enc)
			processCertificateInvalidEntry(tt.args.logentry, tt.args.nodename, tt.args.mid, w)

			assert.Equal(t, tt.want.Type, enc.evt.Type)
			assert.Equal(t, tt.want.Source.Type, enc.evt.Source.Type)
			assert.Equal(t, tt.want.Source.Value, enc.evt.Source.Value)
			assert.Equal(t, tt.want.Source.Extra, enc.evt.Source.Extra)
			assert.Equal(t, tt.want.Outcome, enc.evt.Outcome)
			assert.Equal(t, tt.want.Subjects, enc.evt.Subjects)
			assert.Equal(t, tt.want.Target, enc.evt.Target)

			// TODO(jaosorior): Add assertions for ExtraData
		})
	}
}
