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
//
// Classification, ServerPlanJSON, and ForceEdge land via Phase 3 #55 /
// migration 00010 and reflect the compiler's last verdict on this row.
// They aren't strictly required for the v1 hub — it still recompiles
// the YAML on every Refresh to honour any operator edit that hasn't
// been re-saved through slither-db yet — but the columns exist so the
// future server detection engine (#58) can stream plan IR straight out
// of pg without re-parsing YAML, and so the console can show
// classification on the rule listing.
type Rule struct {
	UID            string
	Name           string
	SourceYAML     string
	UpdatedAt      time.Time
	Classification string
	ServerPlanJSON []byte
	ForceEdge      bool
}

// ListEnabledRules returns every enabled rule, ordered by uid for a
// stable wire shape. Stable order keeps the agent's RuleSet diff
// trivial when only one rule has changed.
func (s *Store) ListEnabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT uid, name, source_yaml, updated_at,
		       classification, server_plan, force_edge
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
		var planRaw []byte
		if err := rows.Scan(&r.UID, &r.Name, &r.SourceYAML, &r.UpdatedAt,
			&r.Classification, &planRaw, &r.ForceEdge); err != nil {
			return nil, fmt.Errorf("pg.ListEnabledRules: scan: %w", err)
		}
		r.ServerPlanJSON = planRaw
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

// UpsertRule inserts a rule row, or updates name/source_yaml/enabled/
// updated_at/updated_by when uid already exists. Operator-facing
// convenience: re-running the insert-rule helper on the same YAML
// edits the row in place rather than failing the unique constraint.
// Returns whether the row was inserted (true) or updated (false).
func (s *Store) UpsertRule(ctx context.Context, uid, name, sourceYAML, updatedBy string, enabled bool) (inserted bool, err error) {
	var updatedByArg any
	if updatedBy != "" {
		u, perr := parseUUID(updatedBy)
		if perr != nil {
			return false, fmt.Errorf("pg.UpsertRule: parse updated_by: %w", perr)
		}
		updatedByArg = u
	}
	var xmaxIsZero bool
	err = s.pool.QueryRow(ctx, `
		INSERT INTO rules (uid, name, source_yaml, enabled, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (uid) DO UPDATE SET
			name = EXCLUDED.name,
			source_yaml = EXCLUDED.source_yaml,
			enabled = EXCLUDED.enabled,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
		RETURNING (xmax = 0) AS inserted
	`, uid, name, sourceYAML, enabled, updatedByArg).Scan(&xmaxIsZero)
	if err != nil {
		return false, fmt.Errorf("pg.UpsertRule: %w", err)
	}
	return xmaxIsZero, nil
}

// UpsertRuleWithClassification is the Phase 3 #55 variant of UpsertRule
// that also persists the compiler's verdict on the YAML — classification
// (edge_only / server_only / both), the JSON-serialised ServerPlan, and
// whether the operator declared force_edge. slither-db insert-rule
// computes these via pkg/ruleast.Compile before inserting so the columns
// land in lock-step with the source_yaml change. classification must be
// one of the values the rules_classification_chk constraint accepts;
// serverPlanJSON may be nil (treated as SQL NULL).
func (s *Store) UpsertRuleWithClassification(
	ctx context.Context,
	uid, name, sourceYAML, updatedBy string,
	enabled bool,
	classification string,
	serverPlanJSON []byte,
	forceEdge bool,
) (inserted bool, err error) {
	var updatedByArg any
	if updatedBy != "" {
		u, perr := parseUUID(updatedBy)
		if perr != nil {
			return false, fmt.Errorf("pg.UpsertRuleWithClassification: parse updated_by: %w", perr)
		}
		updatedByArg = u
	}
	var planArg any
	if len(serverPlanJSON) > 0 {
		planArg = serverPlanJSON
	}
	var xmaxIsZero bool
	err = s.pool.QueryRow(ctx, `
		INSERT INTO rules (uid, name, source_yaml, enabled, updated_by,
		                   classification, server_plan, force_edge)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (uid) DO UPDATE SET
			name = EXCLUDED.name,
			source_yaml = EXCLUDED.source_yaml,
			enabled = EXCLUDED.enabled,
			updated_by = EXCLUDED.updated_by,
			classification = EXCLUDED.classification,
			server_plan = EXCLUDED.server_plan,
			force_edge = EXCLUDED.force_edge,
			updated_at = now()
		RETURNING (xmax = 0) AS inserted
	`, uid, name, sourceYAML, enabled, updatedByArg,
		classification, planArg, forceEdge).Scan(&xmaxIsZero)
	if err != nil {
		return false, fmt.Errorf("pg.UpsertRuleWithClassification: %w", err)
	}
	return xmaxIsZero, nil
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
