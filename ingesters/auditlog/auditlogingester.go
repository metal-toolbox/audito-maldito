// auditlog package processes the /var/log/audit/audit.log log file.
// Process records the stream of text and on newline sends the line of text
// to the AuditLogChan for received by the auditd processor for
// correlation and analysis.
package auditlog

import (
	"context"

	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
	"github.com/metal-toolbox/audito-maldito/internal/health"
)

type AuditLogIngester struct {
	namedPipeIngester namedpipe.NamedPipeIngester
	FilePath          string
	AuditLogChan      chan string
	Logger            *zap.SugaredLogger
	Health            *health.Health
}

func (a *AuditLogIngester) Ingest(ctx context.Context) error {
	return a.namedPipeIngester.Ingest(ctx, a.FilePath, '\n', a.Process, a.Logger, a.Health)
}

func (a *AuditLogIngester) Process(ctx context.Context, line string) error {
	a.AuditLogChan <- line
	return nil
}
