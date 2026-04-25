// Command slither-db applies embedded Postgres migrations for the slither
// server. Subcommands: migrate (apply all pending), reset (rewind to 0
// then re-apply; gated on SLITHER_ALLOW_RESET=1), status (print goose
// migration log), bootstrap-admin (idempotent admin-user seed).
//
// DSN is read from --dsn or $SLITHER_STORAGE_POSTGRES_DSN. Intended for
// docker-compose bootstrap, CI database setup, and local dev loops.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3rmit3/slither/pkg/version"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "slither-db: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dsn := flag.String("dsn", os.Getenv("SLITHER_STORAGE_POSTGRES_DSN"),
		"Postgres DSN (default: $SLITHER_STORAGE_POSTGRES_DSN)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		dirty := ""
		if version.Modified() {
			dirty = "+dirty"
		}
		fmt.Printf("slither-db %s (%s%s)\n", version.Version, version.Revision(), dirty)
		return nil
	}

	if flag.NArg() < 1 {
		usage()
		return fmt.Errorf("expected a subcommand")
	}
	sub := flag.Arg(0)

	if *dsn == "" {
		return fmt.Errorf("--dsn or SLITHER_STORAGE_POSTGRES_DSN required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch sub {
	case "migrate":
		return pg.Migrate(ctx, *dsn)
	case "reset":
		return pg.Reset(ctx, *dsn)
	case "status":
		return pg.Status(ctx, *dsn)
	case "bootstrap-admin":
		return bootstrapAdmin(ctx, *dsn, flag.Args()[1:])
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// bootstrapAdmin seeds an admin user idempotently. Username defaults to
// "admin"; password defaults to $SLITHER_BOOTSTRAP_PASSWORD, falling
// back to a freshly-generated random string printed to stdout.
func bootstrapAdmin(ctx context.Context, dsn string, args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
	username := fs.String("username", "admin", "Admin username to create")
	if err := fs.Parse(args); err != nil {
		return err
	}

	password := os.Getenv("SLITHER_BOOTSTRAP_PASSWORD")
	generated := false
	if password == "" {
		var err error
		password, err = randomPassword()
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		generated = true
	}

	store, err := pg.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("pg open: %w", err)
	}
	defer store.Close()

	id, created, err := store.BootstrapAdmin(ctx, *username, password)
	if err != nil {
		return err
	}
	if !created {
		fmt.Fprintln(os.Stderr, "slither-db: admin user already present, leaving as is")
		return nil
	}
	fmt.Fprintf(os.Stderr, "slither-db: created admin user %s (id=%s)\n", *username, id)
	if generated {
		// Print to stdout so docker-compose logs capture it; never
		// printed when the operator supplied $SLITHER_BOOTSTRAP_PASSWORD.
		fmt.Fprintf(os.Stdout, "username: %s\npassword: %s\n", *username, password)
	}
	return nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 18) // 24 base64 chars, ample entropy.
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `slither-db — Postgres migration harness for slither server.

Usage:
  slither-db [--dsn DSN] <subcommand> [subcommand-flags]

Subcommands:
  migrate                          Apply all pending migrations.
  reset                            Rewind to 0 and re-apply (requires SLITHER_ALLOW_RESET=1).
  status                           Print goose migration state.
  bootstrap-admin [--username U]   Idempotent admin-user seed; prints
                                   credentials to stdout when password is
                                   randomly generated. Honours
                                   $SLITHER_BOOTSTRAP_PASSWORD.

Environment:
  SLITHER_STORAGE_POSTGRES_DSN  default DSN if --dsn not given
  SLITHER_ALLOW_RESET=1         required for the reset subcommand
  SLITHER_BOOTSTRAP_PASSWORD    fixed password for bootstrap-admin
`)
}
