// Package varlogsecure provides a way to read the contents of /var/log/secure
// and process them into ssh login events.
package varlogsecure

import (
	"context"
	"fmt"

	"github.com/metal-toolbox/auditevent"
	"github.com/nxadm/tail"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/health"
	"github.com/metal-toolbox/audito-maldito/internal/metrics"
	"github.com/metal-toolbox/audito-maldito/processors/rocky"
	"github.com/metal-toolbox/audito-maldito/processors/sshd"
)

const (
	// VarLogSecureFilePath is the path to the /var/log/secure file.
	VarLogSecureFilePath = "/var/log/secure"
	// VarLogSecureComponentName is the component name for /var/log/secure.
	VarLogSecureComponentName = "varlogsecure"
)

// VarLogSecure is a helper struct to read from /var/log/secure.
type VarLogSecure struct {
	L             *zap.SugaredLogger
	Logins        chan<- common.RemoteUserLogin
	NodeName      string
	MachineID     string
	AuWriter      *auditevent.EventWriter
	Health        *health.Health
	Metrics       *metrics.PrometheusMetricsProvider
	SshdProcessor *sshd.SshdProcessor
}

// Read reads from /var/log/secure and processes the lines into
// common.RemoteUserLogin events.
// TODO: If the process restarts, this will start reading from the beginning
// of the file. This is not ideal. We should be able to read from where we
// left off.
func (v *VarLogSecure) Read(ctx context.Context) error {
	v.L.Info("reading from /var/log/secure")

	defer v.L.Infoln("rocky worker exited")

	// Create a tail
	t, err := tail.TailFile(
		"/var/log/secure", tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		return err
	}

	defer t.Cleanup()

	r := rocky.RockyProcessor{}

	v.Health.OnReady(VarLogSecureComponentName)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, isOpen := <-t.Lines:
			if !isOpen {
				return fmt.Errorf("/var/log/secure chan closed")
			}
			le, err := r.Process(ctx, line.Text)
			if err != nil {
				v.L.Errorf("error processing rocky secure logs %s", err.Error())
				continue
			}
			if le.PID != "" {
				err := r.SshdProcessor.ProcessSshdLogEntry(ctx, sshd.SshdLogEntry{
					Message: le.Message,
					PID:     le.PID,
				})
				if err != nil {
					return err
				}
			}
		}
	}
}
