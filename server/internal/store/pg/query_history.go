package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// queryHistoryRetentionPerUser caps query_history at this many rows
// per user. Phase 6 #116(a). 50 matches the operator's working memory
// — older queries are pruned every time the writer adds a new row,
// so cardinality stays bounded without a separate sweep job.
const queryHistoryRetentionPerUser = 50

// QueryHistoryRow is one row in the per-user history list.
type QueryHistoryRow struct {
	ID        string
	UserID    string
	Surface   SavedQuerySurface
	Raw       string // URL-encoded query string
	CreatedAt time.Time
}

// RecordQuery appends one row to query_history and prunes the user's
// row count back to the retention cap. The two operations run in the
// same tx so a concurrent caller can't see the sum exceed the cap
// for a transient window.
//
// raw is the full URL-encoded query string the operator submitted
// (everything after `?` on /events?...). Empty raw is silently
// ignored — saving a no-filter view to history is noise.
func (s *Store) RecordQuery(ctx context.Context, userID string, surface SavedQuerySurface, raw string) error {
	if raw == "" {
		return nil
	}
	switch surface {
	case SavedQuerySurfaceEvents, SavedQuerySurfaceAlerts, SavedQuerySurfaceHunts:
	default:
		return fmt.Errorf("pg.RecordQuery: invalid surface %q", surface)
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("pg.RecordQuery: parse user_id: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg.RecordQuery: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit-or-rollback handled below

	if _, err := tx.Exec(ctx, `
		INSERT INTO query_history (user_id, surface, raw)
		VALUES ($1, $2, $3)
	`, uid, string(surface), raw); err != nil {
		return fmt.Errorf("pg.RecordQuery: insert: %w", err)
	}
	// Trim oldest rows above the per-user cap. The DELETE uses a
	// subquery picking the keep-set so a single round-trip handles
	// both prune + insert.
	if _, err := tx.Exec(ctx, `
		DELETE FROM query_history
		WHERE user_id = $1
		  AND id NOT IN (
		      SELECT id FROM query_history
		      WHERE user_id = $1
		      ORDER BY created_at DESC
		      LIMIT $2
		  )
	`, uid, queryHistoryRetentionPerUser); err != nil {
		return fmt.Errorf("pg.RecordQuery: prune: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg.RecordQuery: commit: %w", err)
	}
	return nil
}

// ListQueryHistory returns the user's recent queries newest-first,
// optionally restricted to one surface. Empty surface returns every
// row. limit is clamped to [1, queryHistoryRetentionPerUser].
func (s *Store) ListQueryHistory(ctx context.Context, userID string, surface SavedQuerySurface, limit int) ([]QueryHistoryRow, error) {
	if limit <= 0 {
		limit = queryHistoryRetentionPerUser
	}
	if limit > queryHistoryRetentionPerUser {
		limit = queryHistoryRetentionPerUser
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListQueryHistory: parse user_id: %w", err)
	}

	stmt := `
		SELECT id, user_id, surface, raw, created_at
		FROM query_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	args := []any{uid, limit}
	if surface != "" {
		stmt = `
			SELECT id, user_id, surface, raw, created_at
			FROM query_history
			WHERE user_id = $1 AND surface = $2
			ORDER BY created_at DESC
			LIMIT $3
		`
		args = []any{uid, string(surface), limit}
	}
	rows, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.ListQueryHistory: %w", err)
	}
	defer rows.Close()

	var out []QueryHistoryRow
	for rows.Next() {
		var (
			r      QueryHistoryRow
			rawID  pgtype.UUID
			rawUID pgtype.UUID
			surf   string
		)
		if err := rows.Scan(&rawID, &rawUID, &surf, &r.Raw, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("pg.ListQueryHistory: scan: %w", err)
		}
		r.ID = uuidString(rawID)
		r.UserID = uuidString(rawUID)
		r.Surface = SavedQuerySurface(surf)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pg.ListQueryHistory: iter: %w", err)
	}
	return out, nil
}

// ErrQueryHistoryDisabled — sentinel for callers that want to flag
// "history off" semantics distinctly from "empty list".
var ErrQueryHistoryDisabled = errors.New("pg: query history disabled")
