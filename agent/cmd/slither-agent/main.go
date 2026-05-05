// Command slither-agent runs the Linux endpoint agent.
//
// Two subcommands:
//
//   - slither-agent run    — the long-running daemon (default if no
//     subcommand given, for backward compat with the systemd unit).
//   - slither-agent enroll — first-run enrollment: trade an operator
//     token for a per-host client cert and persist it to the state dir.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/t3rmit3/slither/agent/internal/app"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/enroll"
	"github.com/t3rmit3/slither/agent/internal/selfprotect"
	"github.com/t3rmit3/slither/pkg/version"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// dispatch routes top-level subcommands. A bare `slither-agent` (no
// subcommand) is treated as `run` so existing systemd units keep
// working without an ExecStart edit.
func dispatch(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "run":
			return runCmd(args[1:])
		case "enroll":
			return enrollCmd(args[1:])
		case "verify-logs":
			return verifyLogsCmd(args[1:])
		case "-h", "--help", "help":
			printUsage()
			return nil
		}
	}
	return runCmd(args)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: slither-agent <command> [flags]

Commands:
  run          Run the agent (default)
  enroll       Enrol this host with the slither server
  verify-logs  Walk the tamper-evident chain at /var/lib/slither/log.chain`)
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "/etc/slither/agent.yaml", "Path to agent YAML config")
	showVersion := fs.Bool("version", false, "Print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	banner := buildBanner()
	if *showVersion {
		fmt.Println(banner)
		return nil
	}

	fmt.Fprintln(os.Stderr, banner)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, *configPath); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}

func enrollCmd(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "Server address (host:port) running the enrollment listener")
	token := fs.String("token", "", "Single-use enrollment token issued by an operator")
	stateDir := fs.String("state-dir", "/var/lib/slither", "Directory to persist key + certs + host_id")
	caCert := fs.String("ca-cert", "", "Pre-pinned CA cert PEM used to verify the server")
	insecure := fs.Bool("insecure-skip-verify", false, "Skip server-cert verification (dev only)")
	serverName := fs.String("server-name", "", "Override SNI hostname (defaults to host portion of --server)")
	timeout := fs.Duration("timeout", 30*time.Second, "Overall RPC timeout")
	tpm := fs.Bool("tpm", false, "Seal cert material to the TPM (Phase 6 #118; opt-in, falls back to keyring/file when absent)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res, err := enroll.Enroll(ctx, enroll.Options{
		ServerAddr:         *server,
		Token:              *token,
		StateDir:           *stateDir,
		CAPath:             *caCert,
		InsecureSkipVerify: *insecure,
		ServerName:         *serverName,
		KeystoreTPM:        *tpm,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "enrolled host %s\n", res.HostID)
	fmt.Fprintf(os.Stderr, "  key:     %s\n", res.KeyPath)
	fmt.Fprintf(os.Stderr, "  cert:    %s\n", res.CertPath)
	fmt.Fprintf(os.Stderr, "  ca:      %s\n", res.CAPath)
	fmt.Fprintf(os.Stderr, "  host_id: %s\n", res.HostIDPath)
	return nil
}

// verifyLogsCmd walks /var/lib/slither/log.chain (or --path) and
// reports the chain's integrity. Phase 5 #95.
//
//	exit 0 — chain valid; prints "ok: walked N records"
//	exit 1 — chain break detected; prints "chain break at seq=N: <reason>"
//	exit 2 — operational failure (file unreadable, etc.)
func verifyLogsCmd(args []string) error {
	fs := flag.NewFlagSet("verify-logs", flag.ExitOnError)
	path := fs.String("path", "/var/lib/slither/log.chain", "Path to the chain file")
	since := fs.Duration("since", 0, "Only count records newer than now-DURATION (chain validation always runs from seq=0)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var sinceTime time.Time
	if *since > 0 {
		sinceTime = time.Now().Add(-*since)
	}

	walked, err := selfprotect.VerifyChain(*path, sinceTime)
	if err != nil {
		var cb *selfprotect.ChainBreakError
		if errors.As(err, &cb) {
			fmt.Fprintf(os.Stderr, "%s\n", cb.Error())
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "verify-logs: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("ok: walked %d records\n", walked)
	return nil
}

func buildBanner() string {
	dirty := ""
	if version.Modified() {
		dirty = "+dirty"
	}
	return fmt.Sprintf("slither-agent %s (%s%s)", version.Version, version.Revision(), dirty)
}
