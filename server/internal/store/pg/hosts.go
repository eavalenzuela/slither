package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrHostNotFound is returned when a hosts row lookup misses. Callers
// usually treat this as Unauthenticated since a missing host on the
// mTLS path means the cert was issued by a since-dropped row.
var ErrHostNotFound = errors.New("pg: host not found")

// UpdateHostLastSeen sets hosts.last_seen = now() for hostID. Used by
// the Session handler (#37) on every Heartbeat. Returns ErrHostNotFound
// if no row matches.
func (s *Store) UpdateHostLastSeen(ctx context.Context, hostID string) error {
	id, err := parseUUID(hostID)
	if err != nil {
		return fmt.Errorf("pg.UpdateHostLastSeen: parse host_id: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE hosts SET last_seen = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("pg.UpdateHostLastSeen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrHostNotFound
	}
	return nil
}

// HostExists reports whether hostID is a known, non-revoked host. Used
// by the Session handler to reject cert-CN values that no longer have a
// matching hosts row (cert outlived the row, or operator revoked).
func (s *Store) HostExists(ctx context.Context, hostID string) (bool, error) {
	id, err := parseUUID(hostID)
	if err != nil {
		return false, fmt.Errorf("pg.HostExists: parse host_id: %w", err)
	}
	var exists bool
	err = s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND revoked_at IS NULL)`,
		id).Scan(&exists)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("pg.HostExists: %w", err)
	}
	return exists, nil
}
