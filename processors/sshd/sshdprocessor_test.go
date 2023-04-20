package sshd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
)

// Refer to "go doc -all testing" for more information.
func TestMain(m *testing.M) {
	l := zap.NewNop()
	logger = l.Sugar()
	os.Exit(m.Run())
}

func TestLoginRE_Usernames(t *testing.T) {
	t.Parallel()

	// From "adduser" on Ubuntu:
	// # adduser 'wow/that/is/terrible'
	// adduser: To avoid problems, the username should consist only
	// of letters, digits, underscores, periods, at signs and dashes,
	// and not start with a dash (as defined by IEEE Std 1003.1-2001).
	// For compatibility with Samba machine accounts $ is also supported
	// at the end of the username
	for _, tt := range []struct {
		name string
		sep  string
	}{
		{
			name: "WithDashes",
			sep:  "-",
		},
		{
			name: "WithDollars",
			sep:  "$",
		},
		{
			name: "WithPeriods",
			sep:  ".",
		},
		{
			name: "WithAtSign",
			sep:  "@",
		},
		{
			name: "WithDigit",
			sep:  "1",
		},
		{
			name: "WithUnicode",
			sep:  "🏝️㱋",
		},
	} {
		tt := tt // The linter made me do this. I am sorry.

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			username := "audito" + tt.sep + "maldito" + tt.sep + "testing"

			x := "Accepted publickey for " + username + " from 127.0.0.1 port 59288 " +
				"ssh2: ED25519-CERT SHA256:/5MdxU2dhlUFDW/vEs1uLiA1eLjqjJ0lw7oSiQ1op6A " +
				"ID foo@bar.com (serial 0) CA ED25519 SHA256:OR+UgqGe+Lk3k10mxPdKibVBYpYtGSROfNEBOc4G2M4"

			matches := loginRE.FindStringSubmatch(x)
			if len(matches) == 0 {
				t.Fatal("failed to find string submatch")
			}

			usrIdx := loginRE.SubexpIndex(idxLoginUserName)
			if usrIdx == -1 {
				t.Fatal("failed to find login username index")
			}

			assert.Equal(t, username, matches[usrIdx])
		})
	}
}

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

	ctx := context.Background()

	expectedts, tserr := time.Parse(time.RFC3339, "2666-06-06T00:00:00Z")
	assert.NoError(t, tserr)

	type args struct {
		logentry string
		nodename string
		mid      string
		pid      string
	}
	tests := []struct {
		name                       string
		args                       args
		expectsRemoteUserLoginChan bool
		want                       *auditevent.AuditEvent
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
			expectsRemoteUserLoginChan: true,
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
			expectsRemoteUserLoginChan: true,
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
			expectsRemoteUserLoginChan: true,
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
			pr := prometheus.NewRegistry()

			enc := &testAuditEventEncoder{t: t}
			w := auditevent.NewAuditEventWriter(enc)

			logins := make(chan common.RemoteUserLogin, 1)
			err := ProcessEntry(&ProcessEntryConfig{
				Ctx:       ctx,
				Logins:    logins,
				LogEntry:  tt.args.logentry,
				NodeName:  tt.args.nodename,
				MachineID: tt.args.mid,
				When:      expectedts,
				Pid:       tt.args.pid,
				EventW:    w,
				Metrics:   metrics.NewPrometheusMetricsProviderForRegisterer(pr),
			})
			assert.NoError(t, err)

			compareAuditLogs(t, tt.want, enc.evt)
			if tt.expectsRemoteUserLoginChan {
				select {
				case login := <-logins:
					compareAuditLogs(t, tt.want, login.Source)
					assert.Equal(t, tt.args.pid, fmt.Sprintf("%d", login.PID))
					assert.Equal(t, tt.want.Subjects["userID"], login.CredUserID)

					// Add check for prometheus remote_logins
					gatheredMetrics, err := pr.Gather()
					require.NoError(t, err)
					// NOTE: This grabs all metrics from the default gatherer
					require.Equal(t, 1, len(gatheredMetrics), "expected 1 metric registered")
					for _, metric := range gatheredMetrics {
						if strings.Contains(metric.GetName(), "remote_logins") {
							m := metric.GetMetric()[0]
							require.Equal(t, float64(1), m.GetCounter().GetValue(), "expected 1 remote login")
						}
					}
				default:
					t.Error("expected login event to be sent to channel")
				}
			}

			// TODO(jaosorior): Add assertions for ExtraData
		})
	}
}
