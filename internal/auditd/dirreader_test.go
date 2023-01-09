package auditd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
)

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
		openFn: func() (io.ReadSeekCloser, error) {
			tf.closed = false
			return tf, nil
		},
		lines: linesRead,
	}

	err := rf.read(ctx, fsnotify.Create)
	if err != nil {
		t.Fatal(err)
	}

	err = rf.read(ctx, fsnotify.Write)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < int(intn(t, 100)); i++ {
		switch intn(t, 2) {
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
		openFn: func() (io.ReadSeekCloser, error) {
			return nil, expErr
		},
		lines: make(chan string),
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
		openFn: func() (io.ReadSeekCloser, error) {
			return tf, nil
		},
		lines: make(chan string),
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
		openFn: func() (io.ReadSeekCloser, error) {
			return tf, nil
		},
		lines: make(chan string),
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

	numLines := int(intn(t, 100))

	var data []byte

	for i := 0; i < numLines; i++ {
		lineBytes := intn(t, 400)

		if lineBytes > 0 {
			b := make([]byte, lineBytes)
			_, err := rand.Read(b)
			if err != nil {
				t.Fatal(err)
			}

			data = append(data, hex.EncodeToString(b)...)
		}

		data = append(data, '\n')
	}

	return data
}

func intn(t *testing.T, max int64) int64 {
	t.Helper()

	i, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		t.Fatal(err)
	}

	return i.Int64()
}

// testFileSystem implements the fileSystem interface.
type testFileSystem struct {
	filePathsToFiles map[string]*testFile
}

func (o *testFileSystem) Open(filePath string) (io.ReadSeekCloser, error) {
	f, hasIt := o.filePathsToFiles[filePath]
	if hasIt {
		return f, nil
	}

	return nil, os.ErrNotExist
}

// testFile implements the io.ReadSeekCloser interface.
type testFile struct {
	readErr error
	seekErr error
	closed  bool
	offset  int
	data    []byte
}

func (o *testFile) Read(p []byte) (n int, err error) {
	if o.readErr != nil {
		return 0, o.readErr
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
		return 0, o.seekErr
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

	if nextOffset > len(o.data)-1 {
		return 0, errors.New("offset is greater than the file's size")
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
