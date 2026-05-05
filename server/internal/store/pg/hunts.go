package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// HuntStatus is the state-machine value for a hunts row.
type HuntStatus string

const (
	HuntStatusDispatching HuntStatus = "dispatching"
	HuntStatusRunning     HuntStatus = "running"
	HuntStatusCompleted   HuntStatus = "completed"
	HuntStatusTimedOut    HuntStatus = "timed_out"
	HuntStatusCancelled   HuntStatus = "cancelled"
)

// HuntInsert is the input shape for InsertHunt. The dispatcher fills
// these from the console form's POST body.
type HuntInsert struct {
	DispatchedBy   string // user uuid; required
	Backend        string // "osquery" today
	Query          string // backend-specific text; required
	HostFilter     string // empty == every host
	TimeoutSecs    int    // > 0; defaulted by the migration if zero
	MaxRowsPerHost int    // >= 0
}

// HuntRow projects the hunts table for the dispatcher + console.
type HuntRow struct {
	ID                 string
	DispatchedBy       string
	Backend            string
	Query              string
	HostFilter         string
	TimeoutSecs        int
	MaxRowsPerHost     int
	Status             HuntStatus
	TargetHostCount    int
	CompletedHostCount int
	Error              string
	DispatchedAt       time.Time
	CompletedAt        *time.Time
}

// ErrHuntNotFound is returned by GetHunt when the row does not exist.
var ErrHuntNotFound = errors.New("pg: hunt not found")

// InsertHunt creates a new hunts row in status=dispatching and returns it.
func (s *Store) InsertHunt(ctx context.Context, ins HuntInsert) (HuntRow, error) {
	if ins.DispatchedBy == "" {
		return HuntRow{}, errors.New("pg.InsertHunt: dispatched_by required")
	}
	if ins.Query == "" {
		return HuntRow{}, errors.New("pg.InsertHunt: query required")
	}
	if ins.Backend == "" {
		ins.Backend = "osquery"
	}
	if ins.TimeoutSecs == 0 {
		ins.TimeoutSecs = 60
	}
	if ins.MaxRowsPerHost < 0 {
		return HuntRow{}, errors.New("pg.InsertHunt: max_rows_per_host must be non-negative")
	}

	const sql = `
        INSERT INTO hunts (dispatched_by, backend, query, host_filter,
                           timeout_secs, max_rows_per_host)
        VALUES ($1::uuid, $2, $3, $4, $5, $6)
        RETURNING id::text, dispatched_by::text, backend, query, host_filter,
                  timeout_secs, max_rows_per_host, status,
                  target_host_count, completed_host_count, COALESCE(error, ''),
                  dispatched_at, completed_at`

	var row HuntRow
	if err := s.pool.QueryRow(ctx, sql,
		ins.DispatchedBy, ins.Backend, ins.Query, ins.HostFilter,
		ins.TimeoutSecs, ins.MaxRowsPerHost,
	).Scan(
		&row.ID, &row.DispatchedBy, &row.Backend, &row.Query, &row.HostFilter,
		&row.TimeoutSecs, &row.MaxRowsPerHost, &row.Status,
		&row.TargetHostCount, &row.CompletedHostCount, &row.Error,
		&row.DispatchedAt, &row.CompletedAt,
	); err != nil {
		return HuntRow{}, fmt.Errorf("pg.InsertHunt: %w", err)
	}
	return row, nil
}

// SetHuntDispatched updates target_host_count + flips status to running.
// Called by the manager after fan-out to subscribers completes.
func (s *Store) SetHuntDispatched(ctx context.Context, huntID string, targetHostCount int) error {
	const sql = `
        UPDATE hunts
           SET target_host_count = $2,
               status            = 'running'
         WHERE id = $1::uuid AND status = 'dispatching'`
	tag, err := s.pool.Exec(ctx, sql, huntID, targetHostCount)
	if err != nil {
		return fmt.Errorf("pg.SetHuntDispatched: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("pg.SetHuntDispatched: %w", ErrHuntNotFound)
	}
	return nil
}

// IncHuntCompleted bumps completed_host_count by one and flips status
// to completed when completed_host_count reaches target_host_count.
// Idempotent at the row level — duplicate completes from one host are
// the agent's contract violation, not the dispatcher's.
func (s *Store) IncHuntCompleted(ctx context.Context, huntID string) error {
	const sql = `
        UPDATE hunts
           SET completed_host_count = completed_host_count + 1,
               status               = CASE
                   WHEN completed_host_count + 1 >= target_host_count
                        AND status = 'running'
                   THEN 'completed'
                   ELSE status
               END,
               completed_at         = CASE
                   WHEN completed_host_count + 1 >= target_host_count
                        AND status = 'running'
                   THEN now()
                   ELSE completed_at
               END
         WHERE id = $1::uuid`
	tag, err := s.pool.Exec(ctx, sql, huntID)
	if err != nil {
		return fmt.Errorf("pg.IncHuntCompleted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("pg.IncHuntCompleted: %w", ErrHuntNotFound)
	}
	return nil
}

// SetHuntTimedOut transitions a running hunt to timed_out. No-op when
// the hunt has already completed (timer fires after natural completion).
func (s *Store) SetHuntTimedOut(ctx context.Context, huntID string) error {
	const sql = `
        UPDATE hunts
           SET status       = 'timed_out',
               completed_at = now()
         WHERE id = $1::uuid AND status IN ('dispatching','running')`
	if _, err := s.pool.Exec(ctx, sql, huntID); err != nil {
		return fmt.Errorf("pg.SetHuntTimedOut: %w", err)
	}
	return nil
}

// GetHunt returns the row by id.
func (s *Store) GetHunt(ctx context.Context, id string) (HuntRow, error) {
	const sql = `
        SELECT id::text, dispatched_by::text, backend, query, host_filter,
               timeout_secs, max_rows_per_host, status,
               target_host_count, completed_host_count, COALESCE(error, ''),
               dispatched_at, completed_at
          FROM hunts
         WHERE id = $1::uuid`
	var row HuntRow
	err := s.pool.QueryRow(ctx, sql, id).Scan(
		&row.ID, &row.DispatchedBy, &row.Backend, &row.Query, &row.HostFilter,
		&row.TimeoutSecs, &row.MaxRowsPerHost, &row.Status,
		&row.TargetHostCount, &row.CompletedHostCount, &row.Error,
		&row.DispatchedAt, &row.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return HuntRow{}, ErrHuntNotFound
	}
	if err != nil {
		return HuntRow{}, fmt.Errorf("pg.GetHunt: %w", err)
	}
	return row, nil
}

// HuntHostRef mirrors hunt.HostRef (defined here to avoid an import
// cycle: server/internal/hunt depends on this package). Local typedef
// is fine — the values are concrete strings, not behaviour.
type HuntHostRef struct {
	ID       string
	Hostname string
}

// ListHostsForHuntFilter returns the host fan-out target list. Empty
// filter returns every non-revoked host; non-empty filter narrows on
// case-insensitive substring of either id or hostname.
//
// Revoked hosts are excluded — there is no point queueing a hunt for
// a host the operator has decommissioned.
func (s *Store) ListHostsForHuntFilter(ctx context.Context, filter string) ([]HuntHostRef, error) {
	const sql = `
        SELECT id::text, hostname
          FROM hosts
         WHERE revoked_at IS NULL
           AND ($1 = ''
                OR position(lower($1) IN lower(id::text)) > 0
                OR position(lower($1) IN lower(hostname))  > 0)
         ORDER BY hostname, id`
	rows, err := s.pool.Query(ctx, sql, filter)
	if err != nil {
		return nil, fmt.Errorf("pg.ListHostsForHuntFilter: %w", err)
	}
	defer rows.Close()
	var out []HuntHostRef
	for rows.Next() {
		var r HuntHostRef
		if err := rows.Scan(&r.ID, &r.Hostname); err != nil {
			return nil, fmt.Errorf("pg.ListHostsForHuntFilter: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListHunts returns hunts ordered newest-first up to the cap.
func (s *Store) ListHunts(ctx context.Context, limit int) ([]HuntRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const sql = `
        SELECT id::text, dispatched_by::text, backend, query, host_filter,
               timeout_secs, max_rows_per_host, status,
               target_host_count, completed_host_count, COALESCE(error, ''),
               dispatched_at, completed_at
          FROM hunts
         ORDER BY dispatched_at DESC
         LIMIT $1`
	rows, err := s.pool.Query(ctx, sql, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListHunts: %w", err)
	}
	defer rows.Close()
	var out []HuntRow
	for rows.Next() {
		var r HuntRow
		if err := rows.Scan(
			&r.ID, &r.DispatchedBy, &r.Backend, &r.Query, &r.HostFilter,
			&r.TimeoutSecs, &r.MaxRowsPerHost, &r.Status,
			&r.TargetHostCount, &r.CompletedHostCount, &r.Error,
			&r.DispatchedAt, &r.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("pg.ListHunts: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
