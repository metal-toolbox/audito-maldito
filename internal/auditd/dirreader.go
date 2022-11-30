package auditd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
)

var _ LogReader = &logDirReader{}

// LogReader abstracts reading audit log lines from one or more audit
// log files.
type LogReader interface {
	// Lines returns a read-only channel that receives audit log
	// lines each time a log file is written to.
	Lines() <-chan string
}

// LogDirReader creates and starts a LogReader implementation for
// the specified directory path (e.g., "/var/log/audit").
//
// The reader can be stopped by cancelling the provided context.
// After cancellation, users should call Wait to ensure any open
// files and resources are released.
func LogDirReader(ctx context.Context, dirPath string) (*logDirReader, error) {
	if dirPath == "" {
		return nil, errors.New("directory path is empty")
	}

	// Get the absolute file path so that the Name field
	// in the fsnotify.Event is also absolute.
	var err error
	dirPath, err = filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get abolute path for '%s' - %w", dirPath, err)
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

	r := &logDirReader{
		dirPath:       dirPath,
		initFileNames: sortLogNamesOldToNew(dirEntries),
		watcher:       &fsnotifyWatcher{watcher: watcher},
		fs:            &osFileSystem{},
		lines:         make(chan string),
		done:          make(chan struct{}),
	}

	go r.loop(ctx)

	return r, nil
}

// sortLogNamesOldToNew filters dirEntries for file names that look like
// audit logs and organizes them such that the oldest logs appear at index
// zero in the returned slice. E.g.,
//    0           1           2           3           4
//   [audit.log.4 audit.log.3 audit.log.2 audit.log.1 audit.log]
func sortLogNamesOldToNew(dirEntries []os.DirEntry) []string {
	var oldestToNew []string

	// Filter unwanted files and directories.
	for _, entry := range dirEntries {
		if entry.IsDir() || !strings.Contains(entry.Name(), "audit.log") {
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

// logDirReader implements the LogReader interface.
type logDirReader struct {
	dirPath       string
	initFileNames []string
	watcher       fsWatcher
	fs            fileSystem
	lines         chan string
	done          chan struct{}
	err           error
}

// Lines implements the LogReader.Lines method.
func (o *logDirReader) Lines() <-chan string {
	return o.lines
}

// Wait waits for the log reader to exit. Users should call this method
// to ensure the LogReader's resources have been released (e.g., that
// open files have been closed).
//
// The returned error is always non-nil. When cancelled, the error must
// contain context.Canceled.
func (o *logDirReader) Wait() error {
	<-o.done
	return o.err
}

func (o *logDirReader) loop(ctx context.Context) {
	err := o.loopWithError(ctx)

	_ = o.watcher.Close()
	o.err = err

	close(o.done)
}

// TODO: This ignores errors from the fsnotify.Watcher.
// The "Errors" channel appears to receive only non-fatal
// errors, as a result I feel that ignoring them seems safe.
func (o *logDirReader) loopWithError(ctx context.Context) error {
	initFileDone := make(chan initialFileRead, 1)
	if len(o.initFileNames) > 0 {
		// Force the initFileDone code to run.
		initFileDone <- initialFileRead{}
	}

	initFileIndex := 0

	mainLogPath := filepath.Join(o.dirPath, "audit.log")

	mainLog := &rotatingFile{
		openFn: func() (io.ReadSeekCloser, error) {
			return o.fs.Open(mainLogPath)
		},
		offset: 0,
		lines:  o.lines,
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
				mainLog.offset = done.numBytesRead
			}

			if initFileIndex > len(o.initFileNames)-1 {
				// No initial files remaining.
				o.initFileNames = nil
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
			// TODO: Should this be buffered with a time.Timer?
			if len(o.initFileNames) == 0 && event.Name == mainLogPath {
				// TODO: Should we read in a separate thread?
				// Reads are usually blocking operations that
				// can only be interrupted by closing the
				// relevant file descriptor.
				err := mainLog.read(ctx, event.Op)
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

type rotatingFile struct {
	openFn func() (io.ReadSeekCloser, error)
	offset int64
	lines  chan<- string
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
	switch op {
	case fsnotify.Create, fsnotify.Remove, fsnotify.Rename:
		o.offset = 0
		return nil
	case fsnotify.Write:
		// break.
	default:
		return nil
	}

	// TODO: Do we need retry logic? What will be the constraints?
	// My initial thought is "no", as we can just let k8s
	// restart the process if an error occurs... but then
	// again, will this always be run under k8s?
	f, err := o.openFn()
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Seek(o.offset, io.SeekStart)
	if err != nil {
		return err
	}

	numBytesRead, err := readLines(ctx, f, o.lines)
	if err != nil {
		return err
	}

	o.offset += numBytesRead

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

// fsnotifyWatcher implements the fsWatcher for the fsnotify.Watcher type.
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
	Open(filePath string) (io.ReadSeekCloser, error)
}

// osFileSystem implements fileSystem using Go's os standard library.
type osFileSystem struct{}

func (o *osFileSystem) Open(filePath string) (io.ReadSeekCloser, error) {
	return os.Open(filePath)
}

// readFilePathLines reads all the data from filePath using bufio.ScanLines.
// It writes each line to the lines chan and returns the number of bytes
// read from reader.
func readFilePathLines(ctx context.Context, fsi fileSystem, filePath string, l chan<- string) (int64, error) {
	f, err := fsi.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return readLines(ctx, f, l)
}

// readLines reads data from reader until EOF using bufio.ScanLines.
// It writes each line to the lines chan and returns the number of
// bytes read from reader.
func readLines(ctx context.Context, reader io.Reader, lines chan<- string) (int64, error) {
	counter := &readCounter{reader: reader}

	scanner := bufio.NewScanner(counter)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return counter.count, ctx.Err()
		case lines <- scanner.Text():
			// continue.
		}
	}

	if scanner.Err() != nil {
		return counter.count, scanner.Err()
	}

	return counter.count, nil
}

// readCounter counts the number of bytes read from the inner reader.
type readCounter struct {
	reader io.Reader
	count  int64
}

// Read reads from the inner reader field, functioning identically to
// io.Reader. It tracks the number of bytes read from the reader.
func (o *readCounter) Read(p []byte) (int, error) {
	n, err := o.reader.Read(p)
	o.count += int64(n)
	return n, err
}
