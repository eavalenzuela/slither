// Command slither-ch applies embedded ClickHouse migrations for the
// slither event store. Phase 5 #99 expanded the harness to goose-style
// up/down/status with a --dry-run flag for pre-production review.
//
// Subcommands:
//
//	migrate-up    apply every pending migration
//	migrate-down  roll back one migration
//	status        print goose state
//	migrate       alias for migrate-up (backwards compat with the
//	              Phase 2 #38 entry point)
//
// All write subcommands accept --dry-run, which prints the SQL goose
// would execute without touching the database.
//
// DSN is read from --dsn or $SLITHER_STORAGE_CLICKHOUSE_DSN.
//
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
	rootFlags := flag.NewFlagSet("slither-ch", flag.ContinueOnError)
	dsn := rootFlags.String("dsn", os.Getenv("SLITHER_STORAGE_CLICKHOUSE_DSN"),
		"ClickHouse DSN (default: $SLITHER_STORAGE_CLICKHOUSE_DSN)")
	showVersion := rootFlags.Bool("version", false, "Print version and exit")
	rootFlags.Usage = usage
	if err := rootFlags.Parse(os.Args[1:]); err != nil {
		return err
	}

	if *showVersion {
		dirty := ""
		if version.Modified() {
			dirty = "+dirty"
		}
		fmt.Printf("slither-ch %s (%s%s)\n", version.Version, version.Revision(), dirty)
		return nil
	}

	if rootFlags.NArg() < 1 {
		usage()
		return fmt.Errorf("expected a subcommand")
	}
	sub := rootFlags.Arg(0)
	subArgs := rootFlags.Args()[1:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch sub {
	case "migrate", "migrate-up":
		return migrateUpCmd(ctx, *dsn, subArgs)
	case "migrate-down":
		return migrateDownCmd(ctx, *dsn, subArgs)
	case "status":
		if *dsn == "" {
			return fmt.Errorf("--dsn or SLITHER_STORAGE_CLICKHOUSE_DSN required")
		}
		return ch.Status(ctx, *dsn)
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func migrateUpCmd(ctx context.Context, dsn string, args []string) error {
	fs := flag.NewFlagSet("migrate-up", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "Print SQL that would be applied; don't execute")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dsn == "" {
		return fmt.Errorf("--dsn or SLITHER_STORAGE_CLICKHOUSE_DSN required")
	}
	if *dryRun {
		return ch.DryRunUp(ctx, dsn, os.Stdout)
	}
	return ch.Migrate(ctx, dsn)
}

func migrateDownCmd(ctx context.Context, dsn string, args []string) error {
	fs := flag.NewFlagSet("migrate-down", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "Print SQL that would be applied; don't execute")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dsn == "" {
		return fmt.Errorf("--dsn or SLITHER_STORAGE_CLICKHOUSE_DSN required")
	}
	if *dryRun {
		return ch.DryRunDown(ctx, dsn, os.Stdout)
	}
	return ch.MigrateDown(ctx, dsn)
}

func usage() {
	fmt.Fprintf(os.Stderr, `slither-ch — ClickHouse migration harness for slither server.

Usage:
  slither-ch [--dsn DSN] <subcommand> [subcommand-flags]

Subcommands:
  migrate-up [--dry-run]    apply every pending migration
  migrate-down [--dry-run]  roll back the most recent migration
  status                    print goose state
  migrate                   alias for migrate-up (backwards compat)

Environment:
  SLITHER_STORAGE_CLICKHOUSE_DSN  default DSN if --dsn not given
`)
}
