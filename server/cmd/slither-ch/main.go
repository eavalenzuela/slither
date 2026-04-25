// Command slither-ch applies embedded ClickHouse migrations for the
// slither event store. Subcommands: migrate (apply all pending), status
// (print goose state).
//
// DSN is read from --dsn or $SLITHER_STORAGE_CLICKHOUSE_DSN.
// Reset is intentionally absent (ADR-0031): there is no equivalent of
// pg's truncate-and-replay that an operator wants more often than they
// want protection from accidentally wiping a real cluster.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3rmit3/slither/pkg/version"
	"github.com/t3rmit3/slither/server/internal/store/ch"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "slither-ch: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dsn := flag.String("dsn", os.Getenv("SLITHER_STORAGE_CLICKHOUSE_DSN"),
		"ClickHouse DSN (default: $SLITHER_STORAGE_CLICKHOUSE_DSN)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		dirty := ""
		if version.Modified() {
			dirty = "+dirty"
		}
		fmt.Printf("slither-ch %s (%s%s)\n", version.Version, version.Revision(), dirty)
		return nil
	}

	if flag.NArg() != 1 {
		usage()
		return fmt.Errorf("expected exactly one subcommand")
	}
	sub := flag.Arg(0)

	if *dsn == "" {
		return fmt.Errorf("--dsn or SLITHER_STORAGE_CLICKHOUSE_DSN required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch sub {
	case "migrate":
		return ch.Migrate(ctx, *dsn)
	case "status":
		return ch.Status(ctx, *dsn)
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `slither-ch — ClickHouse migration harness for slither server.

Usage:
  slither-ch [--dsn DSN] <migrate|status>

Environment:
  SLITHER_STORAGE_CLICKHOUSE_DSN  default DSN if --dsn not given
`)
}
