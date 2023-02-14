//go:build int

package integration_tests

import (
	"context"
	_ "embed"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"

	"github.com/metal-toolbox/audito-maldito/internal/app"
	"github.com/metal-toolbox/audito-maldito/internal/common"
)

const (
	testingUser   = "auditomalditotesting"
	testingCertID = "foo@bar.com"

	testingSSHDConfigFilePath = "/etc/ssh/audito-maldito-integration-test_config"
	auditdRulesFilePath       = "/etc/audit/rules.d/audit.rules"
)

var (
	//go:embed testdata/auditd-rules-ubuntu.rules
	auditdRulesUbuntu string

	debug *log.Logger

	zapLoggerFn = func() (*zap.Logger, error) {
		config := zap.NewDevelopmentConfig()
		config.EncoderConfig = zap.NewDevelopmentEncoderConfig()
		config.DisableStacktrace = true
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)

		return config.Build()
	}
)

func TestMain(m *testing.M) {
	u, err := user.Current()
	if err != nil {
		log.Fatalf("failed to lookup current user - %s", err)
	}

	if u.Uid != "0" {
		log.Fatalf("the integration tests must be run as the root user :(")
	}

	os.Exit(m.Run())
}

//nolint:paralleltest // should not run in parallel
func TestSSHCertLoginAndExecStuff_Ubuntu(t *testing.T) {
	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelFn()

	ourPrivateKeyPath := setupUbuntuComputer(t, ctx)

	t.Setenv("NODE_NAME", "integration-test")

	expectedShellPipeline := []appToRun{
		{
			exeName: "hexdump",
			args: []string{
				"-C", "/etc/ssh/sshd_config",
			},
		},
		{
			exeName: "grep",
			args: []string{
				"Permit",
			},
		},
	}

	// Shell pipelines imply the last program in the pipeline
	// gets executed first.
	//
	// E.g., "hexdump -C /etc/ssh/sshd_config | grep Permit"
	// implies "grep" is executed first.
	index := len(expectedShellPipeline) - 1

	verifyErrs := make(chan error, 1)
	readEventsErrs := createPipeAndReadEvents(t, ctx, "/app-audit/audit.log", func(event *auditevent.AuditEvent) {
		if index < 0 {
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
			case <-ctx.Done():
			case verifyErrs <- err:
			}
			return
		}

		if action != "executed" {
			return
		}

		how, hasHow, err := valueFromMetadataExtraMap("how", event.Metadata.Extra)
		if err != nil {
			select {
			case <-ctx.Done():
			case verifyErrs <- err:
			}
			return
		}

		if !hasHow || filepath.Base(how) != expectedShellPipeline[index].exeName {
			return
		}

		index--

		if index < 0 {
			verifyErrs <- nil
		}
	})

	appHealth := common.NewHealth()

	appErrs := make(chan error, 1)
	go func() {
		appErrs <- app.Run(ctx, []string{"audito-maldito"}, appHealth, zapLoggerFn)
	}()

	err := appHealth.WaitForReadyCtxOrTimeout(ctx, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to wait for app to become ready - %s", err)
	}

	err = execSSHPipeline(ctx, ourPrivateKeyPath, expectedShellPipeline)
	if err != nil {
		t.Fatalf("failed to execute ssh pipeline - %s", err)
	}

	select {
	case err = <-appErrs:
		t.Fatalf("app exited unexpectedly - %v", err)
	case err = <-readEventsErrs:
		cancelFn()
		<-appErrs

		t.Fatalf("pipe reader exited unexpectedly - %v", err)
	case err = <-verifyErrs:
		cancelFn()
		<-appErrs

		if err != nil {
			t.Fatalf("failed to verify events - %s", err)
		}
	}
}

// setupUbuntuComputer executes the necessary programs to setup a Ubuntu
// machine for integration tests. This function can be safely run multiple
// times; it is idempotent.
func setupUbuntuComputer(t *testing.T, ctx context.Context) (ourPrivateKeyPath string) {
	t.Helper()

	mustExecApp(t, exec.CommandContext(ctx,
		"apt", "update"))

	mustExecApp(t, exec.CommandContext(ctx,
		"apt", "install",
		"auditd", "openssh-server"))

	mustExecApp(t, exec.CommandContext(ctx,
		"systemctl", "start", "auditd"))

	mustExecApp(t, exec.CommandContext(ctx,
		"systemctl", "start", "sshd"))

	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home directory - %s", err)
	}

	ourPrivateKeyPath = setupSSHCertAccess(t, ctx, homeDirPath)

	testingUserHomeDirPath := "/home/" + testingUser

	_, statErr := os.Stat(testingUserHomeDirPath)
	if statErr == nil {
		mustExecApp(t, exec.CommandContext(ctx,
			"deluser", "--force", "--remove-home", testingUser))
	}

	// https://askubuntu.com/a/94067
	mustExecApp(t, exec.CommandContext(ctx,
		"adduser",
		"--home", testingUserHomeDirPath,
		"--disabled-password", "--gecos", ``, testingUser))

	err = os.WriteFile(
		auditdRulesFilePath,
		[]byte(auditdRulesUbuntu),
		0o600)
	if err != nil {
		t.Fatalf("failed to write auditd rules file - %s", err)
	}

	mustExecApp(t, exec.CommandContext(ctx, "augenrules", "--load"))

	return ourPrivateKeyPath
}
