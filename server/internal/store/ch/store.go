// Package ch wraps the ClickHouse event store (ADR-0031).
//
// Phase 2 §4.1 task #38: migration harness, connection pool, and the
// batched Writer that subscribes to the ingest bus and flushes per-class
// rows to MergeTree tables. Public surface is small on purpose — the
// console + ingest tasks talk to *Store via narrow methods that grow as
// each consumer lands.
package ch

import (
	"context"
	"database/sql"
	"fmt"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Store wraps the native clickhouse-go driver.Conn plus a database/sql
// handle on the same DSN. The native conn is used for prepared-batch
// inserts (the writer's hot path); the sql handle exists so goose can
// run migrations through database/sql like it does for Postgres.
type Store struct {
	conn driver.Conn
	sql  *sql.DB
	dsn  string
}

// Open parses dsn (clickhouse:// or tcp://) and returns a Store after
// pinging both handles. Caller owns Close.
func Open(ctx context.Context, dsn string) (*Store, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("ch.Open: parse dsn: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("ch.Open: native open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ch.Open: ping: %w", err)
	}
	sqlDB := clickhouse.OpenDB(opts)
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ch.Open: sql ping: %w", err)
	}
	return &Store{conn: conn, sql: sqlDB, dsn: dsn}, nil
}

// Conn returns the native driver.Conn for prepared-batch inserts.
func (s *Store) Conn() driver.Conn { return s.conn }

// SQL returns the database/sql handle — used by goose during Migrate
// and by ad-hoc queries that don't justify a native prepared statement.
func (s *Store) SQL() *sql.DB { return s.sql }

// DSN returns the connection string (used by goose to re-open inside
// migration harness; tests also use it to talk to the same instance).
func (s *Store) DSN() string { return s.dsn }

// Close shuts down both handles. Idempotent.
func (s *Store) Close() {
	if s == nil {
		return
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.sql != nil {
		_ = s.sql.Close()
	}
}
