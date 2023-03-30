package app

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/metal-toolbox/auditevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/metal-toolbox/audito-maldito/internal/auditd"
	"github.com/metal-toolbox/audito-maldito/internal/common"
	"github.com/metal-toolbox/audito-maldito/internal/util"
)

const usage = `audito-maldito

DESCRIPTION
  audito-maldito is a daemon that monitors OpenSSH server logins and
  produces structured audit events describing what authenticated users
  did while logged in (e.g., what programs they executed).

OPTIONS
`

var logger *zap.SugaredLogger

func Run(ctx context.Context, osArgs []string, optLoggerConfig *zap.Config) error {
	var bootID string
	var auditlogpath string
	var auditLogDirPath string
	logLevel := zapcore.DebugLevel // TODO: Switch default back to zapcore.ErrorLevel.

	flagSet := flag.NewFlagSet(osArgs[0], flag.ContinueOnError)

	// This is just needed for testing purposes. If it's empty we'll use the current boot ID
	flagSet.StringVar(&bootID, "boot-id", "", "Optional Linux boot ID to use when reading from the journal")
	flagSet.StringVar(&auditlogpath, "audit-log-path", "/app-audit/audit.log", "Path to the audit log file")
	flagSet.StringVar(&auditLogDirPath, "audit-dir-path", "/var/log/audit", "Path to the Linux audit log directory")
	flagSet.Var(&logLevel, "log-level", "Set the log level according to zapcore.Level")
	flagSet.Usage = func() {
		os.Stderr.WriteString(usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	err := flagSet.Parse(osArgs[1:])
	if err != nil {
		return err
	}

	if optLoggerConfig == nil {
		cfg := zap.NewProductionConfig()
		optLoggerConfig = &cfg
	}

	optLoggerConfig.Level = zap.NewAtomicLevelAt(logLevel)

	l, err := optLoggerConfig.Build()
	if err != nil {
		return err
	}

	defer func() {
		_ = l.Sync() //nolint
	}()

	logger = l.Sugar()

	auditd.SetLogger(logger)

	_, err = util.Distro()
	if err != nil {
		return fmt.Errorf("failed to get os distro type: %w", err)
	}

	_, miderr := common.GetMachineID()
	if miderr != nil {
		return fmt.Errorf("failed to get machine id: %w", miderr)
	}

	_, nodenameerr := common.GetNodeName()
	if nodenameerr != nil {
		return fmt.Errorf("failed to get node name: %w", nodenameerr)
	}

	eg, groupCtx := errgroup.WithContext(ctx)

	// open output file
	fo, err := os.Create("output.txt")
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	eventWriter := auditevent.NewDefaultAuditEventWriter(fo)
	logger.Infoln("starting workers...")

	var audit = make(chan string)
	defer close(audit)
	eg.Go(func() error {
		file, err := os.OpenFile("/var/log/audit/audit-pipe", os.O_RDONLY, os.ModeNamedPipe)
		if err != nil {
			log.Fatal(err)
		}

		r := bufio.NewReader(file)
		currentLog := bytes.NewBufferString("")
		buf := make([]byte, 0, 4*1024)

		for {
			n, err := r.Read(buf[:cap(buf)])
			sp := strings.Split(string(buf[:n]), "\n")

			if len(sp) > 1 {
				logger.Infof(currentLog.String() + sp[0])
				audit <- currentLog.String() + sp[0]
				for _, line := range sp[1 : len(sp)-1] {
					audit <- line
				}
				currentLog.Truncate(0)
				currentLog.WriteString(sp[len(sp)-1])

			} else {
				currentLog.Write(buf[:n])
			}

			if err != nil {
				logger.Errorln(err)
			}

			// if n == 0 {
			// 	if err == nil {
			// 		time.Sleep(time.Second * 5)
			// 		logger.Infof("Sleeping for 5. 0 bytes read")
			// 		continue
			// 	}
			// 	if err == io.EOF {
			// 		time.Sleep(time.Second * 5)
			// 		logger.Infof("Sleeping for 5. EOF")
			// 		continue
			// 	}
			// 	log.Fatal(err)
			// }
		}
	})

	eg.Go(func() error {
		// API routes
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			var b []byte
			b, err := ioutil.ReadAll(r.Body)

			if err != nil {
				fmt.Println("Error reading bytes")
			}
			w.WriteHeader(http.StatusAccepted)

			// Push to channel here
			audit <- string(b[:])
		})

		port := ":5000"
		logger.Infof("Server is running on port: %d\n", port)

		// Start server on port specified above
		return http.ListenAndServe(port, nil)

	})

	eg.Go(func() error {
		ap := auditd.Auditd{
			Audits: audit,
			EventW: eventWriter,
		}

		err := ap.Read(groupCtx)
		if logger.Level() == zap.DebugLevel {
			logger.Debugf("audit worker exited (%v)", err)
		}
		return err
	})

	if err := eg.Wait(); err != nil {
		// We cannot treat errors containing context.Canceled
		// as non-errors because the errgroup.Group uses its
		// own context, which is canceled if one of the Go
		// routines returns a non-nil error. Thus, treating
		// context.Canceled as a graceful shutdown may hide
		// an error returned by one of the Go routines.
		return fmt.Errorf("workers finished with error: %w", err)
	}

	logger.Infoln("all workers finished without error")

	return nil
}

// lastReadJournalTimeStamp returns the last-read journal entry's timestamp
// or a sensible default if the timestamp cannot be loaded.
func lastReadJournalTimeStamp() uint64 {
	lastRead, err := common.GetLastRead()
	switch {
	case err != nil:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Warnf("failed to read last read timestamp for journal - "+
			"reading from current time (reason: '%s')", err.Error())
	case lastRead == 0:
		lastRead = uint64(time.Now().UnixMicro())

		logger.Info("last read timestamp for journal is zero - " +
			"reading from current time")
	default:
		logger.Infof("last read timestamp for journal is: '%d'", lastRead)
	}

	return lastRead
}
