package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rule is one enabled rules-table row, projected to the columns the
// control plane (#39) needs to compile a RuleSet. Disabled rows are
// excluded by ListEnabledRules so callers don't have to filter.
type Rule struct {
	UID        string
	Name       string
	SourceYAML string
	UpdatedAt  time.Time
}

// ListEnabledRules returns every enabled rule, ordered by uid for a
// stable wire shape. Stable order keeps the agent's RuleSet diff
// trivial when only one rule has changed.
func (s *Store) ListEnabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT uid, name, source_yaml, updated_at
		FROM rules
		WHERE enabled = true
		ORDER BY uid
	`)
	if err != nil {
		return nil, fmt.Errorf("pg.ListEnabledRules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.UID, &r.Name, &r.SourceYAML, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("pg.ListEnabledRules: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertRule stores a new rule row. Used by the operator CLI / admin
// RPC; tests use it to drive the LISTEN/NOTIFY path. updatedBy may be
// empty for system-driven inserts.
func (s *Store) InsertRule(ctx context.Context, uid, name, sourceYAML, updatedBy string) error {
	var updatedByArg any
	if updatedBy != "" {
		u, err := parseUUID(updatedBy)
		if err != nil {
			return fmt.Errorf("pg.InsertRule: parse updated_by: %w", err)
		}
		updatedByArg = u
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rules (uid, name, source_yaml, updated_by)
		VALUES ($1, $2, $3, $4)
	`, uid, name, sourceYAML, updatedByArg)
	if err != nil {
		return fmt.Errorf("pg.InsertRule: %w", err)
	}
	return nil
}

// SetRuleEnabled toggles the enabled flag and bumps updated_at. The
// trigger fires either way so a flip-then-flop within the LISTEN poll
// window still produces at least one notification.
func (s *Store) SetRuleEnabled(ctx context.Context, uid string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE rules SET enabled = $2, updated_at = now() WHERE uid = $1
	`, uid, enabled)
	if err != nil {
		return fmt.Errorf("pg.SetRuleEnabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("pg.SetRuleEnabled: rule %q not found", uid)
	}
	return nil
}

// WatchRules opens a dedicated connection, LISTENs on rules_changed,
// and invokes onChange for every notification. Blocks until ctx is
// cancelled. The connection is exclusive — pgxpool releases it on
// return so callers don't leak conns on long-running listeners.
//
// Coalescing is the caller's responsibility: many notifications can
// arrive in a tight burst (one per row of a multi-row update) and
// onChange should debounce before re-reading the table.
func (s *Store) WatchRules(ctx context.Context, onChange func()) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("pg.WatchRules: acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN rules_changed"); err != nil {
		return fmt.Errorf("pg.WatchRules: listen: %w", err)
	}

	for {
		_, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return fmt.Errorf("pg.WatchRules: wait: %w", err)
		}
		onChange()
	}
}
