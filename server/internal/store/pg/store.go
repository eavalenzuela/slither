package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store holds the shared pgxpool for every Postgres-backed subsystem.
// Typed CRUD helpers hang off *Store as methods once their owning task
// lands (see package doc in migrate.go).
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to dsn, validates reachability with a Ping, and returns a
// ready-to-use Store. Callers own Close().
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg.Open: parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg.Open: new pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg.Open: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pool for test code and for later tasks that
// need direct Exec/Query access before their typed helper is written.
// Production code should prefer the typed helpers once they exist.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close drains and closes the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
