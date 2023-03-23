package common

import (
	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"
)

// AuditEventWriter abstracts functionality that writes auditevent.AuditEvent.
type AuditEventWriter interface {
	Write(e *auditevent.AuditEvent) error
}

func NewLoggingAuditEventWriter(writer *auditevent.EventWriter, logger *zap.SugaredLogger) AuditEventWriter {
	return &loggingAuditEventWriter{
		writer: writer,
		logger: logger,
	}
}

type loggingAuditEventWriter struct {
	writer *auditevent.EventWriter
	logger *zap.SugaredLogger
}

func (o *loggingAuditEventWriter) Write(e *auditevent.AuditEvent) error {
	if o.logger.Level() == zap.DebugLevel {
		o.logger.Debugln("writing audit event...")
	}

	err := o.writer.Write(e)

	if o.logger.Level() == zap.DebugLevel {
		o.logger.Debugf("finished writing audit event (err was: %v)", err)
	}

	if err != nil {
		return err
	}

	return nil
}
