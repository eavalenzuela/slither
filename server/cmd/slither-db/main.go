// Command slither-db applies embedded Postgres migrations for the slither
// server. Subcommands: migrate (apply all pending), reset (rewind to 0
// then re-apply; gated on SLITHER_ALLOW_RESET=1), status (print goose
// migration log).
//
// DSN is read from --dsn or $SLITHER_STORAGE_POSTGRES_DSN. Intended for
// docker-compose bootstrap, CI database setup, and local dev loops.
package main

import (
	"context"
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

	if flag.NArg() != 1 {
		usage()
		return fmt.Errorf("expected exactly one subcommand")
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
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `slither-db — Postgres migration harness for slither server.

Usage:
  slither-db [--dsn DSN] <migrate|reset|status>

Environment:
  SLITHER_STORAGE_POSTGRES_DSN  default DSN if --dsn not given
  SLITHER_ALLOW_RESET=1         required for the reset subcommand
`)
}
