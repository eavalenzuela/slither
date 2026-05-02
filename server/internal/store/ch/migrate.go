package ch

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers "clickhouse" sql driver
	"github.com/pressly/goose/v3"

	chmig "github.com/t3rmit3/slither/server/clickhouse/migrations"
)

// Migrate applies every pending ClickHouse migration. Safe to call at
// startup — goose no-ops on a database already at head. dsn must be a
// clickhouse://... URL the goose sql driver understands.
func Migrate(ctx context.Context, dsn string) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return migrateDB(ctx, db)
}

// MigrateDown rolls back the most recently applied migration. Phase
// 5 #99 — symmetric to slither-db's reset flow but step-wise so a
// botched OCSF schema bump can be peeled back without nuking the
// store. Errors propagate; the caller decides whether to retry or
// surface to the operator.
func MigrateDown(ctx context.Context, dsn string) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := prepareGoose(); err != nil {
		return err
	}
	if err := goose.DownContext(ctx, db, "."); err != nil {
		return fmt.Errorf("ch.MigrateDown: %w", err)
	}
	return nil
}

// Status prints CH migration state via goose.
func Status(ctx context.Context, dsn string) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := prepareGoose(); err != nil {
		return err
	}
	return goose.StatusContext(ctx, db, ".")
}

// DryRunUp lists the migrations that would be applied by Migrate and
// prints each pending migration's `+goose Up` block to w. No writes
// to the database. Phase 5 #99 — gives operators a "what does
// `slither-ch migrate-up` actually do" preview before pulling the
// trigger on a production cluster.
func DryRunUp(ctx context.Context, dsn string, w io.Writer) error {
	return dryRun(ctx, dsn, w, dryDirectionUp)
}

// DryRunDown is the analogous preview for the most recent applied
// migration's `+goose Down` block.
func DryRunDown(ctx context.Context, dsn string, w io.Writer) error {
	return dryRun(ctx, dsn, w, dryDirectionDown)
}

type dryDirection int

const (
	dryDirectionUp dryDirection = iota
	dryDirectionDown
)

func dryRun(ctx context.Context, dsn string, w io.Writer, dir dryDirection) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := prepareGoose(); err != nil {
		return err
	}

	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return fmt.Errorf("ch.DryRun: db version: %w", err)
	}

	files, err := listMigrationFiles()
	if err != nil {
		return err
	}

	switch dir {
	case dryDirectionUp:
		fmt.Fprintf(w, "-- ch dry-run: pending UP from version %d\n", current)
		emitted := 0
		for _, f := range files {
			if f.version <= current {
				continue
			}
			fmt.Fprintf(w, "\n-- migration %s (v%d) --\n", f.name, f.version)
			body, err := readMigrationSection(f.name, "Up")
			if err != nil {
				return err
			}
			fmt.Fprintln(w, body)
			emitted++
		}
		if emitted == 0 {
			fmt.Fprintln(w, "-- (none — already at head)")
		}
	case dryDirectionDown:
		// Down rolls back the highest-applied migration. Find the
		// file matching `current`.
		fmt.Fprintf(w, "-- ch dry-run: DOWN from version %d\n", current)
		var target *migrationFile
		for i := range files {
			if files[i].version == current {
				target = &files[i]
				break
			}
		}
		if target == nil {
			fmt.Fprintln(w, "-- (no Down — at version 0)")
			return nil
		}
		fmt.Fprintf(w, "\n-- migration %s (v%d) --\n", target.name, target.version)
		body, err := readMigrationSection(target.name, "Down")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, body)
	}
	return nil
}

// migrationFile is one entry from the embedded FS sorted by version.
type migrationFile struct {
	name    string // e.g. "00005_retention_and_cardinality.sql"
	version int64
}

func listMigrationFiles() ([]migrationFile, error) {
	entries, err := chmig.FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("ch.DryRun: read embed: %w", err)
	}
	out := make([]migrationFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		// Filenames are NNNNN_name.sql. Take the leading digits as
		// the goose version.
		var v int64
		for _, ch := range name {
			if ch < '0' || ch > '9' {
				break
			}
			v = v*10 + int64(ch-'0')
		}
		if v == 0 {
			continue
		}
		out = append(out, migrationFile{name: name, version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// readMigrationSection extracts the Up or Down section from one of
// the embedded migration files. Looks for `-- +goose Up` /
// `-- +goose Down` markers that goose itself uses; everything between
// the marker and the next marker (or EOF) is the section body.
func readMigrationSection(name, section string) (string, error) {
	body, err := chmig.FS.ReadFile(path.Clean(name))
	if err != nil {
		return "", fmt.Errorf("ch.DryRun: read %s: %w", name, err)
	}
	marker := "-- +goose " + section
	idx := strings.Index(string(body), marker)
	if idx < 0 {
		return fmt.Sprintf("-- (no %s section)", section), nil
	}
	tail := string(body)[idx+len(marker):]
	// Stop at the next "-- +goose " marker if present.
	if next := strings.Index(tail, "-- +goose "); next >= 0 {
		tail = tail[:next]
	}
	return strings.TrimSpace(tail), nil
}

func openSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("ch: open: %w", err)
	}
	return db, nil
}

func migrateDB(ctx context.Context, db *sql.DB) error {
	if err := prepareGoose(); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("ch.Migrate: up: %w", err)
	}
	return nil
}

func prepareGoose() error {
	goose.SetBaseFS(chmig.FS)
	if err := goose.SetDialect("clickhouse"); err != nil {
		return fmt.Errorf("ch: set dialect: %w", err)
	}
	return nil
}
