package dirreader

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

func TestStartLogDirReader(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tempDirPath := t.TempDir()

	_, err := StartLogDirReader(ctx, tempDirPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStartLogDirReader_EmptyDirPathErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	_, err := StartLogDirReader(ctx, "")
	assert.NotNil(t, err)
}

func TestStartLogDirReader_ReadDirErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	_, err := StartLogDirReader(ctx, "/Function TestRotatingFile_Lifecycle missing the call to method parallel")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestSortLogNamesOldToNew(t *testing.T) {
	t.Parallel()

	in := []fs.DirEntry{
		&testDirEntry{isDir: false, name: "audit.log.3"},
		&testDirEntry{isDir: false, name: "audit.log.2"},
		&testDirEntry{isDir: false, name: "audit.log.4"},
		&testDirEntry{isDir: false, name: "audit.log"},
		&testDirEntry{isDir: false, name: "audit.log.1"},
	}

	result := sortLogNamesOldToNew(in)

	assert.Len(t, result, len(in))

	for i, s := range result {
		switch i {
		case 0:
			assert.Equal(t, s, "audit.log.4")
		case 1:
			assert.Equal(t, s, "audit.log.3")
		case 2:
			assert.Equal(t, s, "audit.log.2")
		case 3:
			assert.Equal(t, s, "audit.log.1")
		case 4:
			assert.Equal(t, s, "audit.log")
		default:
			t.Fatalf("unknown index: %d", i)
		}
	}
}

func TestSortLogNamesOldToNew_Empty(t *testing.T) {
	t.Parallel()

	result := sortLogNamesOldToNew(nil)

	assert.Nil(t, result)
}

func TestSortLogNamesOldToNew_NoDirs(t *testing.T) {
	t.Parallel()

	result := sortLogNamesOldToNew([]fs.DirEntry{
		&testDirEntry{isDir: false, name: "gunner is a dog, not a directory :("},
		&testDirEntry{isDir: false, name: "nope.avi"},
		&testDirEntry{isDir: false, name: "this deal is getting worse all the time"},
	})

	assert.Nil(t, result)
}

func TestSortLogNamesOldToNew_NoMatchingPrefixes(t *testing.T) {
	t.Parallel()

	result := sortLogNamesOldToNew([]fs.DirEntry{
		&testDirEntry{isDir: true, name: "gunner is a dog, not a directory :("},
		&testDirEntry{isDir: true, name: "nope.avi"},
		&testDirEntry{isDir: true, name: "this deal is getting worse all the time"},
	})

	assert.Nil(t, result)
}

func TestLogDirReader_Lines(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	ldr := newTestLogDirReader(ctx, &testFSWatcher{events: make(chan fsnotify.Event)}, &testFileSystem{})

	if ldr.lines != ldr.Lines() {
		t.Fatalf("expected: %T - got: %T", ldr.lines, ldr.Lines())
	}
}

func TestLogDirReader_Wait(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	ldr := newTestLogDirReader(ctx, &testFSWatcher{events: make(chan fsnotify.Event)}, &testFileSystem{})

	cancelFn()

	err := ldr.Wait()
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLogDirReader_OpenMainLogFileErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	fsEvents := make(chan fsnotify.Event, 1)
	fsEvents <- fsnotify.Event{
		Name: "/audit.log",
		Op:   fsnotify.Write,
	}

	ldr := newTestLogDirReader(
		ctx,
		&testFSWatcher{events: fsEvents},
		&testFileSystem{})

	err := ldr.Wait()
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLogDirReader_InitialFileErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	const filePath = "/audit.log"
	expErr := errors.New("i'm cia")

	tfs := &testFileSystem{
		filePathsToFiles: map[string]*testFile{
			filePath: {
				readErr: expErr,
				data:    []byte{0x06, 0x66},
			},
		},
	}

	ldr := newTestLogDirReader(
		ctx,
		&testFSWatcher{events: make(chan fsnotify.Event)},
		tfs,
		filepath.Base(filePath))

	err := ldr.Wait()
	assert.ErrorIs(t, err, expErr)
}

func TestLogDirReader_InitialFileSuccess(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()

	expData := bytes.NewBuffer(nil)
	numFiles := int(testtools.Intn(t, 1, 10))
	initialFileNames := make([]string, numFiles)
	tfs := &testFileSystem{
		filePathsToFiles: make(map[string]*testFile, numFiles),
	}

	for i := 0; i < numFiles; i++ {
		var fileName string

		fileI := numFiles - 1 - i
		if fileI == 0 {
			fileName = "audit.log"
		} else {
			fileName = fmt.Sprintf("audit.log.%d", fileI)
		}

		tf := testFileWithRandomLines(t)
		expData.Write(tf.data)

		initialFileNames[i] = fileName
		tfs.filePathsToFiles["/"+fileName] = tf
	}

	ldr := newTestLogDirReader(
		ctx,
		&testFSWatcher{events: make(chan fsnotify.Event)},
		tfs,
		initialFileNames...)

	resultReady := make(chan *bytes.Buffer, 1)

	go func() {
		lines := bytes.NewBuffer(nil)

		for {
			select {
			case <-ctx.Done():
				return
			case l := <-ldr.Lines():
				lines.WriteString(l)
				lines.WriteByte('\n')

				if lines.Len() >= expData.Len() {
					resultReady <- lines
					return
				}
			}
		}
	}()

	errs := make(chan error, 1)
	go func() {
		errs <- ldr.Wait()
	}()

	select {
	case err := <-errs:
		t.Fatal(err)
	case result := <-resultReady:
		assert.Equal(t, expData.String(), result.String())
	}
}

func newTestLogDirReader(ctx context.Context, fsw fsWatcher, fsi fileSystem, initFileNames ...string) *LogDirReader {
	ldr := &LogDirReader{
		dirPath:       "/",
		initFileNames: initFileNames,
		watcher:       fsw,
		fs:            fsi,
		lines:         make(chan string),
		initFilesDone: make(chan struct{}),
		done:          make(chan struct{}),
	}

	go ldr.loop(ctx)

	return ldr
}

func TestRotatingFile_Lifecycle(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tf := testFileWithRandomLines(t)

	origData := bytes.NewBuffer(nil)
	origData.Write(tf.data)

	bufReady := make(chan *bytes.Buffer, 1)
	linesRead := make(chan string)

	go func() {
		lines := bytes.NewBuffer(nil)

		for {
			select {
			case <-ctx.Done():
				bufReady <- lines
				return
			case l := <-linesRead:
				lines.WriteString(l)
				lines.WriteByte('\n')
			}
		}
	}()

	rf := &rotatingFile{
		openFn: func() (statReadSeekCloser, error) {
			tf.closed = false
			return tf, nil
		},
		lines:  linesRead,
		boConf: backoff.NewExponentialBackOff(),
		boFn: func(operation backoff.Operation, _ backoff.BackOff) error {
			// TODO: How do we handle back-offs in unit tests?
			return operation()
		},
	}

	err := rf.read(ctx, fsnotify.Create)
	if err != nil {
		t.Fatal(err)
	}

	err = rf.read(ctx, fsnotify.Write)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < int(testtools.Intn(t, 0, 100)); i++ {
		switch testtools.Intn(t, 0, 2) {
		case 0:
			tf.Truncate()

			err = rf.read(ctx, fsnotify.Remove)
			if err != nil {
				t.Fatal(err)
			}

			err = rf.read(ctx, fsnotify.Create)
			if err != nil {
				t.Fatal(err)
			}
		case 1:
			more := randomLines(t)
			tf.data = append(tf.data, more...)
			origData.Write(more)

			err = rf.read(ctx, fsnotify.Write)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	cancelFn()

	writtenBuf := <-bufReady

	assert.Equal(t, origData.String(), writtenBuf.String())
}

func TestRotatingFile_OpenErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	expErr := errors.New("got anything to declare")

	rf := &rotatingFile{
		openFn: func() (statReadSeekCloser, error) {
			return nil, expErr
		},
		lines:  make(chan string),
		boConf: backoff.NewExponentialBackOff(),
		boFn: func(operation backoff.Operation, _ backoff.BackOff) error {
			// TODO: How do we handle back-offs in unit tests?
			return operation()
		},
	}

	err := rf.read(ctx, fsnotify.Create)
	if err != nil {
		t.Fatal(err)
	}

	err = rf.read(ctx, fsnotify.Write)
	assert.ErrorIs(t, err, expErr)
}

func TestRotatingFile_SeekErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	expErr := errors.New("AAAAAAAA")

	tf := &testFile{
		seekErr: expErr,
	}

	rf := &rotatingFile{
		openFn: func() (statReadSeekCloser, error) {
			return tf, nil
		},
		lines:  make(chan string),
		boConf: backoff.NewExponentialBackOff(),
		boFn: func(operation backoff.Operation, _ backoff.BackOff) error {
			// TODO: How do we handle back-offs in unit tests?
			return operation()
		},
	}

	err := rf.read(ctx, fsnotify.Create)
	if err != nil {
		t.Fatal(err)
	}

	err = rf.read(ctx, fsnotify.Write)
	assert.ErrorIs(t, err, expErr)
}

func TestRotatingFile_ReadLinesErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	expErr := errors.New("4831c099b03b48bf2f2f62696e2f736848c1ef08574889e757524889e60f05")

	tf := &testFile{
		data:    []byte{0xf0, 0x0d},
		readErr: expErr,
	}

	rf := &rotatingFile{
		openFn: func() (statReadSeekCloser, error) {
			return tf, nil
		},
		lines:  make(chan string),
		boConf: backoff.NewExponentialBackOff(),
		boFn: func(operation backoff.Operation, _ backoff.BackOff) error {
			// TODO: How do we handle back-offs in unit tests?
			return operation()
		},
	}

	err := rf.read(ctx, fsnotify.Create)
	if err != nil {
		t.Fatal(err)
	}

	err = rf.read(ctx, fsnotify.Write)
	assert.ErrorIs(t, err, expErr)
}

func TestOSFileSystem_Open(t *testing.T) {
	t.Parallel()

	osfs := &osFileSystem{}

	_, err := osfs.Open("/course/two/five/zero")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected error type: %T - got: %T", os.ErrNotExist, err)
	}

	f, err := osfs.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func TestReadFilePathLines(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tf := &testFile{
		data: []byte("hello world\n\n\nstick a needle in my eye\nand forget to ever ask you why\nfunky\n"),
	}

	tfs := &testFileSystem{
		filePathsToFiles: map[string]*testFile{
			"/foo/bar": tf,
		},
	}

	bufReady := make(chan *bytes.Buffer, 1)
	linesRead := make(chan string)

	go func() {
		lines := bytes.NewBuffer(nil)

		for {
			select {
			case <-ctx.Done():
				bufReady <- lines
				return
			case l := <-linesRead:
				lines.WriteString(l)
				lines.WriteByte('\n')
			}
		}
	}()

	n, err := readFilePathLines(ctx, tfs, "/foo/bar", linesRead)
	cancelFn()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, int64(len(tf.data)), n)

	linesBuf := <-bufReady

	assert.Equal(t, string(tf.data), linesBuf.String())
}

func TestReadFilePathLines_OpenErr(t *testing.T) {
	t.Parallel()

	_, err := readFilePathLines(
		context.Background(),
		&testFileSystem{},
		"/keepin/the/mic/warm/against/the/norm",
		make(chan string))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected error type: %T - got: %T", os.ErrNotExist, err)
	}
}

func TestReadLines(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tf := testFileWithRandomLines(t)

	bufReady := make(chan *bytes.Buffer, 1)
	linesRead := make(chan string)

	go func() {
		lines := bytes.NewBuffer(nil)

		for {
			select {
			case <-ctx.Done():
				bufReady <- lines
				return
			case l := <-linesRead:
				lines.WriteString(l)
				lines.WriteByte('\n')
			}
		}
	}()

	n, err := readLines(ctx, tf, linesRead)
	cancelFn()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, int64(len(tf.data)), n)

	linesBuf := <-bufReady

	assert.Equal(t, string(tf.data), linesBuf.String())
}

func TestReadLines_ReadErr(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	tf := &testFile{
		readErr: errors.New("smash"),
	}

	_, err := readLines(ctx, tf, nil)
	cancelFn()
	assert.ErrorIs(t, err, tf.readErr)
}

func TestReadLines_Cancel(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	cancelFn()

	tf := &testFile{
		data: []byte("beep boop\n"),
	}

	_, err := readLines(ctx, tf, make(chan string))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected error type: %T - got: %T", context.Canceled, err)
	}
}

func testFileWithRandomLines(t *testing.T) *testFile {
	t.Helper()

	return &testFile{data: randomLines(t)}
}

func randomLines(t *testing.T) []byte {
	t.Helper()

	numLines := int(testtools.Intn(t, 0, 100))

	var data []byte

	for i := 0; i < numLines; i++ {
		lineBytes := testtools.RandomBytes(t, 0, 400)
		if lineBytes != nil {
			data = append(data, hex.EncodeToString(lineBytes)...)
		}

		data = append(data, '\n')
	}

	return data
}

// testDirEntry implements the fs.DirEntry interface.
type testDirEntry struct {
	name  string
	isDir bool
	t     fs.FileMode
	info  fs.FileInfo
	iErr  error
}

func (o *testDirEntry) Name() string {
	return o.name
}

func (o *testDirEntry) IsDir() bool {
	return o.isDir
}

func (o *testDirEntry) Type() fs.FileMode {
	return o.t
}

func (o *testDirEntry) Info() (fs.FileInfo, error) {
	return o.info, o.iErr
}

// testFSWatcher implements the fsWatcher interface.
type testFSWatcher struct {
	events chan fsnotify.Event
}

func (o *testFSWatcher) Events() <-chan fsnotify.Event {
	return o.events
}

func (o *testFSWatcher) Close() error {
	return nil
}

// testFileSystem implements the fileSystem interface.
type testFileSystem struct {
	filePathsToFiles map[string]*testFile
}

func (o *testFileSystem) Open(filePath string) (statReadSeekCloser, error) {
	f, hasIt := o.filePathsToFiles[filePath]
	if hasIt {
		return f, nil
	}

	return nil, backoff.Permanent(os.ErrNotExist)
}

// testFile implements the statReadSeekCloser interface.
type testFile struct {
	statErr error
	readErr error
	seekErr error
	name    string
	mode    fs.FileMode
	modTime time.Time
	closed  bool
	offset  int
	data    []byte
}

func (o *testFile) Stat() (fs.FileInfo, error) {
	if o.statErr != nil {
		return nil, backoff.Permanent(o.statErr)
	}

	return &testFileStat{tf: o}, nil
}

func (o *testFile) Read(p []byte) (n int, err error) {
	if o.readErr != nil {
		return 0, backoff.Permanent(o.readErr)
	}

	if o.closed {
		return 0, os.ErrClosed
	}

	if o.offset > len(o.data)-1 {
		return 0, io.EOF
	}

	n = copy(p, o.data[o.offset:])

	o.offset += n

	return n, nil
}

func (o *testFile) Seek(offset int64, whence int) (int64, error) {
	if o.seekErr != nil {
		return 0, backoff.Permanent(o.seekErr)
	}

	if o.closed {
		return 0, os.ErrClosed
	}

	var nextOffset int

	switch whence {
	case io.SeekStart:
		nextOffset = int(offset)
	case io.SeekCurrent:
		nextOffset = o.offset + int(offset)
	case io.SeekEnd:
		nextOffset = len(o.data) - 1 - int(offset)
	default:
		return 0, fmt.Errorf("unknown whence value: %d", whence)
	}

	if nextOffset < 0 {
		return 0, errors.New("offset is negative")
	}

	// You would think we should check len(o.data)-1,
	// but that is handled by the Read method.
	if nextOffset > len(o.data) {
		return 0, fmt.Errorf("offset is greater than the file's size of %d", len(o.data))
	}

	o.offset = nextOffset

	return int64(nextOffset), nil
}

func (o *testFile) Truncate() {
	o.data = nil
	o.offset = 0
}

func (o *testFile) Close() error {
	o.closed = true
	return nil
}

// testFileStat implements the fs.FileInfo interface.
type testFileStat struct {
	tf *testFile
}

func (o *testFileStat) Name() string {
	return o.tf.name
}

func (o *testFileStat) Size() int64 {
	return int64(len(o.tf.data))
}

func (o *testFileStat) Mode() fs.FileMode {
	return o.tf.mode
}

func (o *testFileStat) ModTime() time.Time {
	return o.tf.modTime
}

func (o *testFileStat) IsDir() bool {
	return false
}

func (o *testFileStat) Sys() any {
	return nil
}
