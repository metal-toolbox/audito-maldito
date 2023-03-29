package auditd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/elastic/go-libaudit/v2/auparse"
)

const (
	auditLogPath = "/var/log/audit/audit.log"
)

type AuditLogReader struct {
	lines chan *auparse.AuditMessage
	fi    *fileRuntime
}

func NewAuditLogReader() (*AuditLogReader, error) {
	lf, err := os.Open(auditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file - %w", err)
	}

	info, err := os.Stat(auditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat audit log file - %w", err)
	}

	//nolint:forcetypeassert // we know the type of the underlying file
	inode := info.Sys().(*syscall.Stat_t).Ino

	return &AuditLogReader{
		lines: make(chan *auparse.AuditMessage),
		fi:    initFileRuntime(lf, inode),
	}, nil
}

func (r *AuditLogReader) Lines() <-chan *auparse.AuditMessage {
	return r.lines
}

func (r *AuditLogReader) Close() {
	close(r.lines)
}

func (r *AuditLogReader) Read(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if _, err := r.fi.ResetFileOffest(); err != nil {
			return fmt.Errorf("failed to reset file offset - %w", err)
		}

		// read the audit log using the underlying file.
		// If the file is rotated, the file will be closed and
		// re-opened.
		// If the file is truncated, the file will be re-opened
		// and the offset will be reset to the beginning of the
		// file.
		// If the file simply reaches EOF, the file will be
		// the file will stay as-is and we'll start the scanner
		// from the current offset.
		scanner := bufio.NewScanner(r.fi.lf)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			line := scanner.Text()

			// skip empty lines
			if line == "" {
				continue
			}

			// parse the line
			msg, err := auparse.ParseLogLine(line)
			if err != nil {
				logger.Errorf("failed to parse audit log line - %v", err)
				// Skips this line and attempts to parse it again
				// on the next iteration. This is meant to catch
				// a case where the audit log line is incomplete
				// and the scanner has read the line but not yet
				// reached the end of the line.
				break
			}

			r.fi.IncreaseOffset(int64(len(line) + 1))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case r.lines <- msg:
			}
		}

		if err := scanner.Err(); err != nil {
			if errors.Is(err, io.EOF) {
				logger.Errorf("failed to read audit log file - %v", err)
				return fmt.Errorf("failed to read audit log file - %w", err)
			}
		}

		info, err := r.fi.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat audit log file - %w", err)
		}

		if r.fi.fileWasRotated(info) {
			if err := r.fi.handleRotation(); err != nil {
				return fmt.Errorf("failed to handle audit log rotation - %w", err)
			}
		}

		// File was truncated
		if r.fi.fileWasTruncated(info) {
			if err := r.fi.handleTruncated(); err != nil {
				return fmt.Errorf("failed to handle audit log truncation - %w", err)
			}
		}
	}
}

type fileRuntime struct {
	lf        *os.File
	fileMutex sync.Mutex
	offset    int64
	inode     uint64
}

func initFileRuntime(lf *os.File, inode uint64) *fileRuntime {
	return &fileRuntime{
		lf:     lf,
		offset: 0,
		inode:  inode,
	}
}

func (r *fileRuntime) Read(p []byte) (int, error) {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	n, err := r.lf.Read(p)
	r.offset += int64(n)

	return n, err
}

func (r *fileRuntime) ResetFileOffest() (int64, error) {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	// Reset the offset to what we last read
	offset, err := r.lf.Seek(r.offset, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to seek audit log file - %w", err)
	}

	return offset, nil
}

func (r *fileRuntime) Close() error {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	return r.lf.Close()
}

func (r *fileRuntime) Stat() (os.FileInfo, error) {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	return r.lf.Stat()
}

func (r *fileRuntime) Inode() uint64 {
	return r.inode
}

func (r *fileRuntime) Offset() int64 {
	return r.offset
}

func (r *fileRuntime) IncreaseOffset(offset int64) {
	r.offset += offset
}

func (r *fileRuntime) fileWasRotated(info os.FileInfo) bool {
	//nolint:forcetypeassert // we know the type of the underlying file
	return info.Sys().(*syscall.Stat_t).Ino != r.inode
}

func (r *fileRuntime) fileWasTruncated(info os.FileInfo) bool {
	return info.Size() < r.offset
}

func (r *fileRuntime) handleRotation() error {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	if err := r.lf.Close(); err != nil {
		logger.Errorf("failed to close audit log file - %w", err)
	}

	// Re-open the file
	var err error
	r.lf, err = os.Open(auditLogPath)
	if err != nil {
		return fmt.Errorf("failed to open audit log file - %w", err)
	}

	return nil
}

func (r *fileRuntime) handleTruncated() error {
	r.fileMutex.Lock()
	defer r.fileMutex.Unlock()

	if _, err := r.lf.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek audit log file - %w", err)
	}

	r.offset = 0

	return nil
}
