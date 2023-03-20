//go:build int

package integration_tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"
)

var (
	debug *log.Logger
)

func zapLoggerConfig() *zap.Config {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig = zap.NewDevelopmentEncoderConfig()
	config.DisableStacktrace = true
	config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)

	return &config
}

// setupSSHCertAccess generates a SSH CA and a private key for the current
// user. It then issues an SSH certificate for the user's key pair.
func setupSSHCertAccess(t *testing.T, ctx context.Context, homeDirPath string) (userKeyPairPath string) {
	t.Helper()

	sshDirPath := filepath.Join(homeDirPath, ".ssh")

	err := os.MkdirAll(sshDirPath, 0o700)
	if err != nil {
		t.Fatalf("failed to create ssh data directory for '%s' - %s", homeDirPath, err)
	}

	sshUserDirInfos, err := os.ReadDir(sshDirPath)
	if err != nil {
		t.Fatalf("failed to read ssh dir path - %s", err)
	}

	// Remove any existing test-related SSH CAs and key pairs.
	for _, info := range sshUserDirInfos {
		if info.IsDir() {
			continue
		}

		if strings.Contains(info.Name(), testingUser) {
			_ = os.Remove(filepath.Join(sshDirPath, info.Name()))
		}
	}

	caPrivateKeyFilePath := filepath.Join(sshDirPath, "ca_"+testingUser)

	// Generate the CA private key.
	//
	// Refer to the "CERTIFICATES" section of "man ssh-keygen"
	// for more information.
	mustExecApp(t, exec.CommandContext(ctx,
		"ssh-keygen",
		"-t", "ed25519", "-N", "", "-f", caPrivateKeyFilePath))

	ourPrivateKeyFilePath := filepath.Join(sshDirPath, "id_"+testingUser)

	// Generate our (the simulated remote user's) SSH private key.
	mustExecApp(t, exec.CommandContext(ctx,
		"ssh-keygen",
		"-t", "ed25519", "-N", "", "-f", ourPrivateKeyFilePath))

	// Issue an SSH certificate for the user's key pair.
	mustExecApp(t, exec.CommandContext(ctx,
		"ssh-keygen",
		"-s", caPrivateKeyFilePath,
		"-I", testingCertID,
		"-n", testingUser,
		ourPrivateKeyFilePath+".pub"))

	// Create sshd config file with details like "trust this CA".
	// See "man sshd" for more information.
	err = os.WriteFile(
		testingSSHDConfigFilePath,
		[]byte("TrustedUserCAKeys "+caPrivateKeyFilePath+".pub\n"),
		0o700)
	if err != nil {
		t.Fatalf("failed to write custom sshd config file - %s", err)
	}

	sshdConfig, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		t.Fatalf("failed to read existing sshd config file - %s", err)
	}

	// Include the previously-generated sshd config file by
	// adding a single line to the primary sshd config file.
	configIncludeDirective := []byte("\nInclude " + testingSSHDConfigFilePath + "\n")
	if !bytes.Contains(sshdConfig, configIncludeDirective) {
		sshdConfig = append(sshdConfig, configIncludeDirective...)

		err = os.WriteFile("/etc/ssh/sshd_config", sshdConfig, 0o700)
		if err != nil {
			t.Fatalf("failed to write updated sshd config file - %s", err)
		}

		mustExecApp(t, exec.CommandContext(ctx,
			"systemctl", "reload", "sshd"))
	}

	return ourPrivateKeyFilePath
}

// createPipeAndReadEvents creates a named pipe (see "man mkfifo") for use
// with the underlying audit event encoder and then starts a Go routine
// that receives audit events as they are written to the named pipe.
func createPipeAndReadEvents(
	t *testing.T, ctx context.Context, eventsPipeFilePath string, onEventFn func(event *auditevent.AuditEvent),
) <-chan error {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(eventsPipeFilePath), 0o700)
	if err != nil {
		t.Fatalf("failed to create events pipe directory - %s", err)
	}

	_ = os.Remove(eventsPipeFilePath)

	err = syscall.Mkfifo(eventsPipeFilePath, 0o600)
	if err != nil {
		t.Fatalf("failed to create events pipe - %s", err)
	}

	cat := exec.CommandContext(ctx, "cat", eventsPipeFilePath)

	stdoutPipe, err := cat.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get stdout pipe for '%s' - %s", cat.String(), err)
	}

	err = cat.Start()
	if err != nil {
		t.Fatalf("failed to execute '%s' - %s", cat.String(), err)
	}

	catErrs := make(chan error, 1)
	go func() {
		defer stdoutPipe.Close()

		scanner := bufio.NewScanner(stdoutPipe)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				catErrs <- ctx.Err()
				return
			default:
			}

			var event auditevent.AuditEvent

			err := json.Unmarshal(scanner.Bytes(), &event)
			if err != nil {
				catErrs <- fmt.Errorf("failed to parse auditevent json '%s' - %w",
					scanner.Text(), err)
				return
			}

			onEventFn(&event)
		}

		err = cat.Wait()
		if err != nil {
			catErrs <- err
			return
		}

		catErrs <- scanner.Err()
	}()

	return catErrs
}

// newShellPipelineChecker creates a new shellPipelineChecker that examines
// audit events generated audito-maldito and checks that they contain the
// provided shell pipeline.
//
// It returns a channel will receive any errors related to checking
// the pipeline and a callback function for use with createPipeAndReadEvents.
func newShellPipelineChecker(ctx context.Context, pipeline []appToRun) (<-chan error, func(*auditevent.AuditEvent)) {
	if len(pipeline) == 0 {
		panic("shell pipeline is empty")
	}

	errs := make(chan error, 1)

	checker := &shellPipelineChecker{
		ctx:      ctx,
		pipeline: pipeline,
		// Shell pipelines imply the last program in the pipeline
		// gets executed first.
		//
		// E.g., "hexdump -C /etc/ssh/sshd_config | grep Permit"
		// implies "grep" is executed first.
		index: len(pipeline) - 1,
		errs:  errs,
	}

	return errs, checker.onEvent
}

type shellPipelineChecker struct {
	ctx      context.Context //nolint
	pipeline []appToRun
	index    int
	errs     chan<- error
}

func (o *shellPipelineChecker) onEvent(event *auditevent.AuditEvent) {
	if o.index < 0 {
		// No applications remaining in pipeline.
		return
	}

	if userName := event.Subjects["loggedAs"]; userName != testingUser {
		return
	}

	if userID := event.Subjects["userID"]; userID != testingCertID {
		return
	}

	if debug != nil {
		debug.Printf("createPipeAndReadEvents event: %+v", event)
	}

	action, _, err := valueFromMetadataExtraMap("action", event.Metadata.Extra)
	if err != nil {
		select {
		case <-o.ctx.Done():
		case o.errs <- err:
		}
		return
	}

	if action != "executed" {
		return
	}

	how, hasHow, err := valueFromMetadataExtraMap("how", event.Metadata.Extra)
	if err != nil {
		select {
		case <-o.ctx.Done():
		case o.errs <- err:
		}
		return
	}

	if !hasHow || filepath.Base(how) != o.pipeline[o.index].exeName {
		return
	}

	o.index--

	if o.index < 0 {
		select {
		case <-o.ctx.Done():
		case o.errs <- nil:
		}
	}
}

// valueFromMetadataExtraMap attempts to extract the value for key from the
// provided map and type-assert it to a string type.
//
// The function returns a non-nil error if it encounters a value that
// is not a string.
func valueFromMetadataExtraMap(key string, metadataExtra map[string]any) (string, bool, error) {
	v, hssIt := metadataExtra[key]
	if !hssIt {
		return "", false, nil
	}

	vStr, ok := v.(string)
	if !ok {
		return "", false, fmt.Errorf("found '%s' in extra map, but it is not a string type - it is: %T",
			key, v)
	}

	return vStr, true, nil
}

// appToRun configures an application prior to execution.
type appToRun struct {
	// exeName is the name of an executable
	// to execute (e.g., "hexdump").
	exeName string

	// args are optional arguments to pass to the process.
	args []string
}

// execSSHPipeline connects to the SSH server running on loopback TCP port 22
// and authenticates using the specified private key. It then executes the
// specified pipeline.
//
// This simulates a user logging in via SSH and executing programs.
func execSSHPipeline(ctx context.Context, ourPrivateKeyPath string, pipeline []appToRun) error {
	pipelineBuf := bytes.NewBuffer(nil)

	for i, cmd := range pipeline {
		pipelineBuf.WriteString(cmd.exeName)

		if len(cmd.args) > 0 {
			for _, arg := range cmd.args {
				pipelineBuf.WriteByte(' ')
				pipelineBuf.WriteString(arg)
			}
		}

		if len(pipeline) != 1 && i != len(pipeline)-1 {
			pipelineBuf.WriteString(" | ")
		}
	}

	// Ignoring the host key is acceptable in this
	// scenario because nothing sensitive is being
	// sent over the connection and the connection
	// is occurring in an ephemeral test setup via
	// loopback. Normally, this would be a terrible
	// idea - but it is OK here.
	sshToLoopback := exec.CommandContext(ctx,
		"ssh",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-i", ourPrivateKeyPath,
		testingUser+"@127.0.0.1",
		pipelineBuf.String())

	err := execApp(sshToLoopback)
	if err != nil {
		return fmt.Errorf("ssh failure ('%s') - %s",
			sshToLoopback.String(), err)
	}

	return nil
}

// mustExecApp wraps execApp. It fails the current test if execApp returns
// a non-nil error.
func mustExecApp(t *testing.T, app *exec.Cmd) {
	err := execApp(app)
	if err != nil {
		t.Fatalf("failed to exec '%s' - %s", app.String(), err)
	}
}

// execApp executes an external application and writes its stderr and stdout
// to a log.Logger.
func execApp(app *exec.Cmd) error {
	log.Printf("executing '%s'...", app.String())

	app.Stderr = newWriterLogger("[" + app.Args[0] + "/stderr] ")
	app.Stdout = newWriterLogger("[" + app.Args[0] + "/stdout] ")

	return app.Run()
}

// newWriterLogger creates a new writerLogger.
func newWriterLogger(prefix string) *writerLogger {
	return &writerLogger{
		buf:    bytes.NewBuffer(nil),
		logger: log.New(log.Writer(), prefix, log.Flags()|log.Lmsgprefix),
	}
}

// writerLogger buffers writes and then writes newlines to the
// underlying log.Logger.
type writerLogger struct {
	buf    *bytes.Buffer
	logger *log.Logger
}

func (o *writerLogger) Write(p []byte) (n int, err error) {
	o.buf.Write(p)

	if !bytes.Contains(p, []byte{'\n'}) {
		return len(p), nil
	}

	for {
		line, err := o.buf.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				// No new line found - write what
				// was read from the buffer back
				// into the buffer.
				o.buf.WriteString(line)
				break
			}

			return 0, fmt.Errorf("failed to read until newline from buffered output - %w", err)
		}

		o.logger.Println(line[0 : len(line)-1])
	}

	return len(p), nil
}
