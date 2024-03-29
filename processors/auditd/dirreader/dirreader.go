package dirreader

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/cenkalti/backoff/v4"
	"github.com/fsnotify/fsnotify"
)

const (
	// DirReaderComponentName is the component name for the dir reader.
	// This is used for health checks.
	DirReaderComponentName = "auditlog-dirreader"
)

// StartLogDirReader creates and starts a LogDirReader for
// the specified directory path (e.g., "/var/log/audit").
//
// The reader can be stopped by cancelling the provided context.
// After cancellation, users should call Wait to ensure any open
// files and resources are released.
func StartLogDirReader(ctx context.Context, dirPath string) (*LogDirReader, error) {
	if dirPath == "" {
		return nil, errors.New("directory path is empty")
	}

	// Get the absolute file path so that the Name field
	// in the fsnotify.Event is also absolute.
	var err error
	dirPath, err = filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for '%s' - %w", dirPath, err)
	}

	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory '%s' - %w", dirPath, err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create new fsnotify.Watcher - %w", err)
	}

	err = watcher.Add(dirPath)
	if err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("failed to add dir path '%s' to watcher - %w", dirPath, err)
	}

	r := &LogDirReader{
		dirPath:       dirPath,
		initFileNames: sortLogNamesOldToNew(dirEntries),
		watcher:       &fsnotifyWatcher{watcher: watcher},
		fs:            &osFileSystem{},
		lines:         make(chan string),
		initFilesDone: make(chan struct{}),
		done:          make(chan struct{}),
	}

	go r.loop(ctx)

	return r, nil
}

// sortLogNamesOldToNew filters dirEntries for file names that look like
// audit logs and organizes them such that the oldest logs appear at index
// zero in the returned slice. E.g.,
//
//	 0           1           2           3           4
//	[audit.log.4 audit.log.3 audit.log.2 audit.log.1 audit.log]
func sortLogNamesOldToNew(dirEntries []os.DirEntry) []string {
	// We pre-allocate the slice to the maximum possible capacity size
	// We don't know how many files will be filtered out, so we can't
	// pre-allocate the slice to the exact size (we don't touch the length).
	oldestToNew := make([]string, 0, len(dirEntries))

	// Filter unwanted files and directories.
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "audit.log") {
			continue
		}

		oldestToNew = append(oldestToNew, entry.Name())
	}

	if len(oldestToNew) == 0 {
		return nil
	}

	// Sort slice such that "audit.log.2" comes before "audit.log.1".
	//
	// Example:
	//   $ ls /var/log/audit/
	//   audit.log  audit.log.1  audit.log.2  audit.log.3  audit.log.4
	//   $ test-app /var/log/audit/
	//   [audit.log.4 audit.log.3 audit.log.2 audit.log.1 audit.log]
	sort.Slice(oldestToNew, func(i, j int) bool {
		return oldestToNew[i] > oldestToNew[j]
	})

	return oldestToNew
}

// LogDirReader reads audit logs from a directory and tails the active
// audit log. It also gracefully handles log file rotation.
type LogDirReader struct {
	dirPath       string
	initFileNames []string
	watcher       fsWatcher
	fs            fileSystem
	lines         chan string
	initFilesDone chan struct{}
	done          chan struct{}
	err           error
}

// Lines returns a read-only channel that receives audit log lines
// each time a log file is written to.
func (o *LogDirReader) Lines() <-chan string {
	return o.lines
}

// Wait waits for the log reader to exit. Users should call this method
// to ensure the LogDirReader's resources have been released (e.g., that
// open files have been closed).
//
// The returned error is always non-nil. When cancelled, the error must
// contain context.Canceled.
func (o *LogDirReader) Wait() error {
	<-o.done
	return o.err
}

func (o *LogDirReader) InitFilesDone() <-chan struct{} {
	return o.initFilesDone
}

func (o *LogDirReader) loop(ctx context.Context) {
	err := o.loopWithError(ctx)

	_ = o.watcher.Close()
	o.err = err

	close(o.done)
}

// Note: This ignores errors from the fsnotify.Watcher.
// The "Errors" channel appears to receive only non-fatal
// errors, as a result I feel that ignoring them seems safe.
func (o *LogDirReader) loopWithError(ctx context.Context) error {
	initFileDone := make(chan initialFileRead, 1)
	if len(o.initFileNames) > 0 {
		// Force the initFileDone code to run.
		initFileDone <- initialFileRead{}
	} else {
		close(o.initFilesDone)
	}

	initFileIndex := 0

	mainLogPath := filepath.Join(o.dirPath, "audit.log")

	mainLog := &rotatingFile{
		openFn: func() (statReadSeekCloser, error) {
			return o.fs.Open(mainLogPath)
		},
		lines:  o.lines,
		boConf: backoff.NewExponentialBackOff(),
		boFn:   backoff.Retry,
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case done := <-initFileDone:
			if done.err != nil {
				return fmt.Errorf("failed to read lines from initial audit log '%s' - %w",
					done.filePath, done.err)
			}

			if done.filePath == mainLogPath {
				mainLog.setOffset(done.numBytesRead)
			}

			if initFileIndex > len(o.initFileNames)-1 {
				// No initial files remaining.
				o.initFileNames = nil
				close(o.initFilesDone)
				continue
			}

			filePath := filepath.Join(o.dirPath, o.initFileNames[initFileIndex])
			go func() {
				numBytes, err := readFilePathLines(ctx, o.fs, filePath, o.lines)
				initFileDone <- initialFileRead{
					filePath:     filePath,
					numBytesRead: numBytes,
					err:          err,
				}
			}()

			initFileIndex++
		case event := <-o.watcher.Events():
			if len(o.initFileNames) == 0 &&
				len(event.Name) == len(mainLogPath) &&
				event.Name == mainLogPath {
				err := mainLog.readWithRetry(ctx, event.Op)
				if err != nil {
					return fmt.Errorf("failed to read from main audit log - %w", err)
				}
			}
		}
	}
}

type initialFileRead struct {
	filePath     string
	numBytesRead int64
	err          error
}

// rotatingFile tails lines from a file that is rotated by
// a logging mechanism.
type rotatingFile struct {
	openFn func() (statReadSeekCloser, error)
	lastSz int64
	offset int64
	lines  chan<- string
	boConf backoff.BackOff
	boFn   func(backoff.Operation, backoff.BackOff) error
}

func (o *rotatingFile) setOffset(i int64) {
	atomic.StoreInt64(&o.offset, i)
}

func (o *rotatingFile) incOffsetBy(i int64) int64 {
	return atomic.AddInt64(&o.offset, i)
}

func (o *rotatingFile) getOffset() int64 {
	return atomic.LoadInt64(&o.offset)
}

// readWithRetry calls read and retries according to the configured back-off.
func (o *rotatingFile) readWithRetry(ctx context.Context, op fsnotify.Op) error {
	return o.boFn(func() error {
		err := o.read(ctx, op)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Force back-off retry to exit.
				// See backoff.Retry for details.
				return backoff.Permanent(err)
			}

			return err
		}

		return nil
	}, o.boConf)
}

// read attempts to read from the reader returned by the openFn field
// if a fsnotify.Write occurs and updates the offset so that subsequent
// reads resume where it left off.
func (o *rotatingFile) read(ctx context.Context, op fsnotify.Op) error {
	// fsnotify events during a file rotation:
	//
	// 2022/11/23 16:46:21 event: WRITE  "/var/log/audit/audit.log"
	// 2022/11/23 16:46:21 event: CHMOD  "/var/log/audit/audit.log"
	// 2022/11/23 16:46:21 event: RENAME "/var/log/audit/audit.log.3"
	// 2022/11/23 16:46:21 event: CREATE "/var/log/audit/audit.log.4"
	// 2022/11/23 16:46:21 event: RENAME "/var/log/audit/audit.log.2"
	// 2022/11/23 16:46:21 event: CREATE "/var/log/audit/audit.log.3"
	// 2022/11/23 16:46:21 event: RENAME "/var/log/audit/audit.log.1"
	// 2022/11/23 16:46:21 event: CREATE "/var/log/audit/audit.log.2"
	// 2022/11/23 16:46:21 event: RENAME "/var/log/audit/audit.log"
	// 2022/11/23 16:46:21 event: CREATE "/var/log/audit/audit.log.1"
	// 2022/11/23 16:46:21 event: CREATE "/var/log/audit/audit.log"
	// 2022/11/23 16:46:21 event: CHMOD  "/var/log/audit/audit.log"
	//
	//nolint:exhaustive // We only care about a subset of the fsnotify events.
	switch op {
	case fsnotify.Create, fsnotify.Remove, fsnotify.Rename:
		o.setOffset(0)
		return nil
	case fsnotify.Write:
		// break.
	default:
		return nil
	}

	f, err := o.openFn()
	if err != nil {
		return fmt.Errorf("failed to open rotating file - %w", err)
	}
	defer f.Close()

	fInfo, err := f.Stat()
	if err != nil {
		o.setOffset(0)
		return err
	}

	currentSizeBytes := fInfo.Size()

	if currentSizeBytes < o.lastSz {
		// If true, then the file was likely rotated, so we need
		// to start from the beginning of the file.
		o.setOffset(0)
	}

	o.lastSz = currentSizeBytes

	off := o.getOffset()
	_, err = f.Seek(off, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to offset %d in rotating file - %w", off, err)
	}

	numBytesRead, err := readLines(ctx, f, o.lines)
	if err != nil {
		return fmt.Errorf("failed to read lines from rotating file starting at offset %d - %w",
			off, err)
	}

	o.incOffsetBy(numBytesRead)

	return nil
}

// fsWatcher abstracts file system event watchers.
type fsWatcher interface {
	// Events returns a read-only channel that receives fsnotify.Event
	// when a file system event occurs.
	Events() <-chan fsnotify.Event

	// Close closes the fsWatcher.
	Close() error
}

// fsnotifyWatcher implements the fsWatcher interface for the
// fsnotify.Watcher type.
type fsnotifyWatcher struct {
	watcher *fsnotify.Watcher
}

func (o *fsnotifyWatcher) Events() <-chan fsnotify.Event {
	return o.watcher.Events
}

func (o *fsnotifyWatcher) Close() error {
	return o.watcher.Close()
}

// fileSystem abstracts a file system similar to Go's io/fs standard library.
type fileSystem interface {
	// Open opens a file for the given path.
	Open(filePath string) (statReadSeekCloser, error)
}

// statReadSeekCloser abstracts a file that uses the os.Stat function and the
// io.ReadSeekCloser interface.
type statReadSeekCloser interface {
	Stat() (fs.FileInfo, error)
	io.ReadSeekCloser
}

// osFileSystem implements fileSystem using Go's os standard library.
type osFileSystem struct{}

func (o *osFileSystem) Open(filePath string) (statReadSeekCloser, error) {
	return os.Open(filePath)
}

// readFilePathLines reads from filePath and writes each line to
// the lines chan. It then returns the total number of bytes read
// in terms of lines processed (i.e., if it reads 100 bytes, but
// only 90 of those bytes were lines ending with a newline, it
// returns 90). Buffered data is not counted in the byte count.
//
// It is similar to os.ReadFile - but avoids reading the entire
// file's contents into memory at once.
//
// An io.EOF error is not returned to the caller.
func readFilePathLines(ctx context.Context, fsi fileSystem, filePath string, l chan<- string) (int64, error) {
	f, err := fsi.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return readLines(ctx, f, l)
}

// readLines reads from reader and writes each line to the lines chan.
// It then returns the total number of bytes read in terms of lines
// processed (i.e., if it reads 100 bytes, but only 90 of those bytes
// were lines ending with a newline, it returns 90). Buffered data is
// not counted in the byte count.
//
// An io.EOF error is not returned to the caller.
func readLines(ctx context.Context, reader io.Reader, lines chan<- string) (int64, error) {
	bufioReader := bufio.NewReader(reader)
	var numBytesRead int64

	for {
		lineRaw, err := bufioReader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return numBytesRead, nil
			}

			return numBytesRead, err
		}

		lineLen := len(lineRaw)

		numBytesRead += int64(lineLen)

		var line string
		if lineLen > 0 {
			// Remove the trailing newline character.
			//
			// Yes, this can result in an empty string.
			// Allowing an empty string maintains
			// backwards compatibility with our
			// existing unit tests.
			line = lineRaw[0 : lineLen-1]
		}

		select {
		case <-ctx.Done():
			return numBytesRead, ctx.Err()
		case lines <- line:
			// continue.
		}
	}
}
