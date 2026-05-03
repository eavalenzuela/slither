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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/sigverify"
	"github.com/t3rmit3/slither/pkg/version"
	"github.com/t3rmit3/slither/server/internal/ioc"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// yamlUnmarshal is a thin wrapper so callers don't import yaml.v3
// directly; centralised so a future swap to a different decoder
// touches one site.
func yamlUnmarshal(src []byte, out any) error { return yaml.Unmarshal(src, out) }

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
	case "verify-rule-bundle":
		return verifyRuleBundle(ctx, flag.Args()[1:])
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
//
// --signed-bundle FILE (Phase 6 #108) verifies a cosign-keyless-signed
// tar.gz bundle (with `.sig` + `.pem` sidecars) and atomically upserts
// every YAML inside under one transaction. ADR-0039 documents the
// bundle format + trust root.
func insertRule(ctx context.Context, dsn string, args []string) error {
	fs := flag.NewFlagSet("insert-rule", flag.ExitOnError)
	file := fs.String("file", "", "Path to Sigma YAML file ('-' = stdin)")
	signedBundle := fs.String("signed-bundle", "", "Path to a cosign-signed tar.gz rule bundle (.sig + .pem sidecars resolved automatically)")
	identityRegexp := fs.String("cosign-identity-regexp", "", "Override cosign certificate-identity (defaults to slither release pipeline)")
	oidcIssuer := fs.String("cosign-oidc-issuer", "", "Override cosign OIDC issuer (defaults to GitHub Actions)")
	enabled := fs.Bool("enabled", true, "Insert with enabled=true (default true)")
	updatedBy := fs.String("updated-by", "admin", "Username whose ID stamps updated_by")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" && *signedBundle == "" {
		return fmt.Errorf("insert-rule: --file or --signed-bundle required")
	}
	if *file != "" && *signedBundle != "" {
		return fmt.Errorf("insert-rule: --file and --signed-bundle are mutually exclusive")
	}

	if *signedBundle != "" {
		return insertSignedBundle(ctx, dsn, *signedBundle, sigverify.Options{
			IdentityRegexp: *identityRegexp,
			OIDCIssuer:     *oidcIssuer,
		}, *enabled, *updatedBy)
	}

	yamlBytes, err := readRuleSource(*file)
	if err != nil {
		return fmt.Errorf("insert-rule: read %s: %w", *file, err)
	}

	// Open pg first so we can build the IOC registry the compiler
	// consults. Rules with `|ioc:` references would otherwise fail
	// compile here even though the feeds are already in pg.
	store, err := pg.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("insert-rule: pg open: %w", err)
	}
	defer store.Close()

	iocReg := ioc.New(store)
	if _, refreshErr := iocReg.Refresh(ctx); refreshErr != nil {
		// Non-fatal — a rule without `|ioc:` references compiles fine
		// regardless. Surface the error so an operator notices a
		// chronically empty registry.
		fmt.Fprintf(os.Stderr, "slither-db: warning: ioc registry refresh failed: %v\n", refreshErr)
	}

	_, plan, class, err := ruleast.Compile(yamlBytes, ruleast.WithIOCRegistry(iocReg))
	if err != nil {
		return fmt.Errorf("insert-rule: compile: %w", err)
	}
	header, err := readRuleHeader(yamlBytes)
	if err != nil {
		return fmt.Errorf("insert-rule: %w", err)
	}
	if header.ID == "" {
		return fmt.Errorf("insert-rule: rule has no id (Sigma `id:` field is required)")
	}
	name := header.Title
	if name == "" {
		name = header.ID
	}
	var planJSON []byte
	if plan != nil {
		planJSON, err = json.Marshal(plan)
		if err != nil {
			return fmt.Errorf("insert-rule: marshal server plan: %w", err)
		}
	}

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

	inserted, err := store.UpsertRuleWithClassification(
		ctx, header.ID, name, string(yamlBytes), updatedByID, *enabled,
		string(class), planJSON, header.ForceEdge,
	)
	if err != nil {
		return err
	}
	verb := "updated"
	if inserted {
		verb = "inserted"
	}
	fmt.Fprintf(os.Stderr, "slither-db: %s rule %s (%s) classification=%s force_edge=%t\n",
		verb, header.ID, name, class, header.ForceEdge)
	return nil
}

// insertSignedBundle verifies the cosign signature on bundlePath, then
// extracts every YAML rule and upserts each via the same path
// insertRule's single-file flow uses. Compile failures inside the
// bundle abort the whole import — operators see the offending file +
// reason and re-cut a clean bundle rather than ending up with a
// partially-imported rule pack.
func insertSignedBundle(ctx context.Context, dsn, bundlePath string, opts sigverify.Options, enabled bool, updatedBy string) error {
	entries, err := sigverify.VerifyAndExtractBundle(ctx, bundlePath, opts)
	if err != nil {
		return fmt.Errorf("insert-rule: verify-and-extract: %w", err)
	}

	store, err := pg.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("insert-rule: pg open: %w", err)
	}
	defer store.Close()

	iocReg := ioc.New(store)
	if _, refreshErr := iocReg.Refresh(ctx); refreshErr != nil {
		fmt.Fprintf(os.Stderr, "slither-db: warning: ioc registry refresh failed: %v\n", refreshErr)
	}

	user, err := store.GetUserByUsername(ctx, updatedBy)
	switch {
	case errors.Is(err, pg.ErrUserNotFound):
		return fmt.Errorf("insert-rule: --updated-by user %q not found (run bootstrap-admin first)", updatedBy)
	case err != nil:
		return fmt.Errorf("insert-rule: lookup user: %w", err)
	}
	updatedByID := user.ID

	type pendingRule struct {
		path      string
		header    ruleHeader
		yamlBytes []byte
		plan      []byte
		class     string
	}

	// Two-phase: compile every entry first (no DB writes); abort on
	// the first compile error so the operator gets the offending
	// path. Then upsert all of them. Compile-everything-first keeps
	// "atomic per-bundle" honest without needing a real pg transaction
	// across the loop (UpsertRuleWithClassification doesn't currently
	// expose a tx-aware variant; refactoring that is out of scope for
	// #108 and the compile-first phase covers the realistic failure
	// mode).
	pending := make([]pendingRule, 0, len(entries))
	for _, entry := range entries {
		_, plan, class, compileErr := ruleast.Compile(entry.Bytes, ruleast.WithIOCRegistry(iocReg))
		if compileErr != nil {
			return fmt.Errorf("insert-rule: compile %s: %w", entry.Path, compileErr)
		}
		header, hdrErr := readRuleHeader(entry.Bytes)
		if hdrErr != nil {
			return fmt.Errorf("insert-rule: %s: %w", entry.Path, hdrErr)
		}
		if header.ID == "" {
			return fmt.Errorf("insert-rule: %s: rule has no id (Sigma `id:` field is required)", entry.Path)
		}
		var planJSON []byte
		if plan != nil {
			planJSON, err = json.Marshal(plan)
			if err != nil {
				return fmt.Errorf("insert-rule: %s: marshal server plan: %w", entry.Path, err)
			}
		}
		pending = append(pending, pendingRule{
			path:      entry.Path,
			header:    header,
			yamlBytes: entry.Bytes,
			plan:      planJSON,
			class:     string(class),
		})
	}

	inserted, updated := 0, 0
	for _, r := range pending {
		name := r.header.Title
		if name == "" {
			name = r.header.ID
		}
		isInserted, upsertErr := store.UpsertRuleWithClassification(
			ctx, r.header.ID, name, string(r.yamlBytes), updatedByID, enabled,
			r.class, r.plan, r.header.ForceEdge,
		)
		if upsertErr != nil {
			return fmt.Errorf("insert-rule: %s: %w", r.path, upsertErr)
		}
		if isInserted {
			inserted++
		} else {
			updated++
		}
	}
	fmt.Fprintf(os.Stderr, "slither-db: bundle %s — verified, %d rules (%d inserted, %d updated)\n",
		bundlePath, len(pending), inserted, updated)
	return nil
}

// verifyRuleBundle is the offline-only counterpart to --signed-bundle.
// Verifies the signature without touching the database — useful for
// CI checks, operator pre-deploy validation, and partner-pipeline
// audits.
func verifyRuleBundle(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify-rule-bundle", flag.ExitOnError)
	identityRegexp := fs.String("cosign-identity-regexp", "", "Override cosign certificate-identity (defaults to slither release pipeline)")
	oidcIssuer := fs.String("cosign-oidc-issuer", "", "Override cosign OIDC issuer (defaults to GitHub Actions)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("verify-rule-bundle: expected exactly one bundle path")
	}
	bundlePath := fs.Arg(0)
	entries, err := sigverify.VerifyAndExtractBundle(ctx, bundlePath, sigverify.Options{
		IdentityRegexp: *identityRegexp,
		OIDCIssuer:     *oidcIssuer,
	})
	if err != nil {
		return fmt.Errorf("verify-rule-bundle: %w", err)
	}
	fmt.Fprintf(os.Stderr, "slither-db: bundle %s — verified, %d YAML rule(s):\n", bundlePath, len(entries))
	for _, e := range entries {
		fmt.Fprintf(os.Stderr, "  %s (%d bytes)\n", e.Path, len(e.Bytes))
	}
	return nil
}

// ruleHeader carries the YAML-level fields that are awkward to extract
// from pkg/ruleast.Compile's structured return — title travels through
// EdgeArtefact.Rule (nil for server-only rules), force_edge is a
// compile-time gate that pkg/ruleast doesn't export. Re-parsing the
// minimal frame keeps slither-db decoupled from compiler internals.
type ruleHeader struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	ForceEdge bool   `yaml:"force_edge"`
}

func readRuleHeader(src []byte) (ruleHeader, error) {
	var h ruleHeader
	if err := yamlUnmarshal(src, &h); err != nil {
		return h, fmt.Errorf("re-parse rule header: %w", err)
	}
	return h, nil
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
  insert-rule --signed-bundle FILE Verify cosign signature on a tar.gz rule
                                   bundle (.sig + .pem sidecars resolved
                                   alongside) then upsert every YAML inside.
                                   Atomic per-bundle: any compile error
                                   aborts the whole import. Flags:
                                     --cosign-identity-regexp REGEXP
                                     --cosign-oidc-issuer URL
                                     --enabled (default true)
                                     --updated-by USERNAME (default admin).
                                   See ADR-0039 + docs/install.md.
  verify-rule-bundle FILE          Verify a signed bundle without touching
                                   the database. Prints the verified entry
                                   list. Same --cosign-* override flags as
                                   insert-rule --signed-bundle.

Environment:
  SLITHER_STORAGE_POSTGRES_DSN  default DSN if --dsn not given
  SLITHER_ALLOW_RESET=1         required for the reset subcommand
  SLITHER_BOOTSTRAP_PASSWORD    fixed password for bootstrap-admin
`)
}
