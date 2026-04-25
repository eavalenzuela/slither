package ch

import (
	"context"
	"database/sql"
	"fmt"

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
