//go:build integration

// Package pg integration tests run against an ephemeral Postgres launched
// via testcontainers-go. Requires a reachable docker daemon — skipped
// cleanly on hosts without one so `make test-integration` on a docker-less
// laptop degrades gracefully rather than failing.

package pg

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	pgcontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// expectedTables is the full set of tables the v1 migrations must create,
// independent of migration-file names. Order-insensitive comparison.
var expectedTables = []string{
	"alerts",
	"audit_log",
	"enrollment_tokens",
	"host_response_policies",
	"hosts",
	"iocs",
	"response_actions",
	"rules",
	"sessions",
	"users",
}

func TestMigrationsApplyCleanOnEmptyDatabase(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	got := listPublicTables(ctx, t, dsn)
	if !sameStringSet(got, expectedTables) {
		t.Errorf("tables = %v, want %v", got, expectedTables)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		if err := Migrate(ctx, dsn); err != nil {
			t.Fatalf("Migrate pass %d: %v", i+1, err)
		}
	}
	got := listPublicTables(ctx, t, dsn)
	if !sameStringSet(got, expectedTables) {
		t.Errorf("tables after 3x Migrate = %v, want %v", got, expectedTables)
	}
}

func TestResetRewindsAndReapplies(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Reset must refuse without the opt-in env var.
	if err := Reset(ctx, dsn); err == nil {
		t.Fatal("Reset without SLITHER_ALLOW_RESET=1 unexpectedly succeeded")
	}
	t.Setenv("SLITHER_ALLOW_RESET", "1")
	if err := Reset(ctx, dsn); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got := listPublicTables(ctx, t, dsn)
	if !sameStringSet(got, expectedTables) {
		t.Errorf("tables after Reset = %v, want %v", got, expectedTables)
	}
}

func TestOpenAndPool(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if s.Pool() == nil {
		t.Fatal("Pool() returned nil")
	}
	var n int
	if err := s.Pool().QueryRow(ctx, "SELECT 1").Scan(&n); err != nil || n != 1 {
		t.Errorf("SELECT 1 → n=%d err=%v", n, err)
	}
}

// requireDocker skips when no docker socket is reachable — matches the
// privileged-BTF skip pattern in the agent integration tests.
func requireDocker(t *testing.T) {
	t.Helper()
	if sock := os.Getenv("DOCKER_HOST"); sock != "" {
		return
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skipf("pg integration: docker not reachable (%v); skipping", err)
	}
	// Probe the socket to catch permission issues early (better diagnostic
	// than letting testcontainers time out).
	c, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
	if err != nil {
		t.Skipf("pg integration: docker socket dial failed (%v); skipping", err)
	}
	_ = c.Close()
}

func startPostgres(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()
	container, err := pgcontainer.Run(ctx,
		"postgres:16-alpine",
		pgcontainer.WithDatabase("slither_test"),
		pgcontainer.WithUsername("slither"),
		pgcontainer.WithPassword("slither"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg container start: %v", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("pg connection string: %v", err)
	}
	return dsn, func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(termCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("container terminate: %v", err)
		}
	}
}

// listPublicTables returns the names of user tables in the public schema.
// goose's own bookkeeping table is filtered out so comparison against
// expectedTables is stable regardless of goose internals.
func listPublicTables(ctx context.Context, t *testing.T, dsn string) []string {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		  AND table_name <> 'goose_db_version'
	`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
