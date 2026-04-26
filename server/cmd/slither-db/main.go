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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/t3rmit3/slither/pkg/ruleast"
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
	case "insert-rule":
		return insertRule(ctx, *dsn, flag.Args()[1:])
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

// insertRule reads a Sigma YAML file (or stdin), validates that it
// compiles via pkg/ruleast, then upserts it into the rules table. The
// uid stamped on the row comes from the compiled rule's `id` so an
// operator can't accidentally write a row whose uid disagrees with
// the YAML body. updatedBy resolves a username through the users
// table; defaults to "admin".
func insertRule(ctx context.Context, dsn string, args []string) error {
	fs := flag.NewFlagSet("insert-rule", flag.ExitOnError)
	file := fs.String("file", "", "Path to Sigma YAML file ('-' = stdin)")
	enabled := fs.Bool("enabled", true, "Insert with enabled=true (default true)")
	updatedBy := fs.String("updated-by", "admin", "Username whose ID stamps updated_by")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("insert-rule: --file required ('-' for stdin)")
	}

	yamlBytes, err := readRuleSource(*file)
	if err != nil {
		return fmt.Errorf("insert-rule: read %s: %w", *file, err)
	}

	compiled, err := ruleast.CompileSigma(yamlBytes)
	if err != nil {
		return fmt.Errorf("insert-rule: compile: %w", err)
	}
	if compiled.ID == "" {
		return fmt.Errorf("insert-rule: rule has no id (Sigma `id:` field is required)")
	}
	name := compiled.Title
	if name == "" {
		name = compiled.ID
	}

	store, err := pg.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("insert-rule: pg open: %w", err)
	}
	defer store.Close()

	var updatedByID string
	user, err := store.GetUserByUsername(ctx, *updatedBy)
	switch {
	case errors.Is(err, pg.ErrUserNotFound):
		return fmt.Errorf("insert-rule: --updated-by user %q not found (run bootstrap-admin first)", *updatedBy)
	case err != nil:
		return fmt.Errorf("insert-rule: lookup user: %w", err)
	default:
		updatedByID = user.ID
	}

	inserted, err := store.UpsertRule(ctx, compiled.ID, name, string(yamlBytes), updatedByID, *enabled)
	if err != nil {
		return err
	}
	verb := "updated"
	if inserted {
		verb = "inserted"
	}
	fmt.Fprintf(os.Stderr, "slither-db: %s rule %s (%s)\n", verb, compiled.ID, name)
	return nil
}

// readRuleSource returns the bytes of path, or all of stdin when path
// is "-". Anything else hits the filesystem so operators can pass a
// path inside a docker volume mount.
func readRuleSource(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	// #nosec G304 -- operator-supplied YAML path; insert-rule is a CLI
	// admin tool, not a network endpoint.
	return os.ReadFile(path)
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
  insert-rule --file YAML          Validate Sigma YAML via pkg/ruleast and
                                   upsert into the rules table. Use '-' to
                                   read from stdin. Flags:
                                     --enabled (default true)
                                     --updated-by USERNAME (default admin).

Environment:
  SLITHER_STORAGE_POSTGRES_DSN  default DSN if --dsn not given
  SLITHER_ALLOW_RESET=1         required for the reset subcommand
  SLITHER_BOOTSTRAP_PASSWORD    fixed password for bootstrap-admin
`)
}
