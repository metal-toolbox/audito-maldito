// auditlog package processes the /var/log/audit/audit.log log file.
// Process records the stream of text and on newline sends the line of text
// to the AuditLogChan for received by the auditd processor for
// correlation and analysis.
package auditlog

import (
	"context"

	"github.com/metal-toolbox/audito-maldito/ingesters/namedpipe"
)

func NewAuditLogIngester(
	filePath string,
	auditLogChan chan string,
	namedPipeIngester namedpipe.NamedPipeIngester,
) AuditLogIngester {
	return AuditLogIngester{
		FilePath:          filePath,
		AuditLogChan:      auditLogChan,
		namedPipeIngester: namedPipeIngester,
	}
}

type AuditLogIngester struct {
	namedPipeIngester namedpipe.NamedPipeIngester
	FilePath          string
	AuditLogChan      chan string
}

func (a *AuditLogIngester) Ingest(ctx context.Context) error {
	return a.namedPipeIngester.Ingest(ctx, a.FilePath, '\n', a.Process)
}

func (a *AuditLogIngester) Process(ctx context.Context, line string) error {
	a.AuditLogChan <- line
	return nil
}
