// Package pg wraps the Postgres control plane (ADR-0030).
//
// Phase 2 §4.1 task #32: migration harness + connection pool. Typed CRUD
// helpers per table land with their consumer tasks (#34 hosts +
// enrollment_tokens, #39 rules, #41 users, #44 revocation).
package pg

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver with database/sql
	"github.com/pressly/goose/v3"

	"github.com/t3rmit3/slither/server/migrations"
)

// Migrate applies every pending migration in embedded order. Safe to call
// at every server startup — goose no-ops on a database already at head.
func Migrate(ctx context.Context, dsn string) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return migrateDB(ctx, db)
}

// Reset drops every migration back to zero and re-applies them. Intended
// for test fixtures + `slither-db reset` against a local dev database.
// Refuses to run unless SLITHER_ALLOW_RESET=1 is set — makes accidental
// production use loud without polluting the DSN with unrecognised params.
func Reset(ctx context.Context, dsn string) error {
	if os.Getenv("SLITHER_ALLOW_RESET") != "1" {
		return fmt.Errorf("pg.Reset: refusing without SLITHER_ALLOW_RESET=1")
	}
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := prepareGoose(); err != nil {
		return err
	}
	if err := goose.DownToContext(ctx, db, ".", 0); err != nil {
		return fmt.Errorf("pg.Reset: down: %w", err)
	}
	return migrateDB(ctx, db)
}

// Status prints migration state to stdout via goose.
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

func openSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: open: %w", err)
	}
	return db, nil
}

func migrateDB(ctx context.Context, db *sql.DB) error {
	if err := prepareGoose(); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("pg.Migrate: up: %w", err)
	}
	return nil
}

func prepareGoose() error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("pg: set dialect: %w", err)
	}
	return nil
}
