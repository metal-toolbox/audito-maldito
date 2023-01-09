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

	"github.com/stretchr/testify/assert"
)

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

	tfs := &testFileSystem{}

	_, err := tfs.Open("/keepin/the/mic/warm/against/the/norm")
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
		err: errors.New("smash"),
	}

	_, err := readLines(ctx, tf, nil)
	cancelFn()
	if !errors.Is(err, tf.err) {
		t.Fatalf("expected error type: %T - got: %T", tf.err, err)
	}
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
	err    error
	closed bool
	offset int
	data   []byte
}

func (o *testFile) Read(p []byte) (n int, err error) {
	if o.err != nil {
		return 0, o.err
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
	if o.err != nil {
		return 0, o.err
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

func (o *testFile) Close() error {
	o.closed = true
	return nil
}
