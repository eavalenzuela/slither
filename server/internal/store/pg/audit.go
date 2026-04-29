package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuditRow is the read-side projection of audit_log used by the
// forensics view. id stays a stringified int64 since the table uses
// bigserial; the console templ never does arithmetic on it.
type AuditRow struct {
	ID         string
	ActorType  ActorType
	ActorID    string
	Action     string
	TargetKind string
	TargetID   string
	Detail     map[string]any
	CreatedAt  time.Time
}

// ListAuditByTarget returns every audit_log row for (kind, id),
// newest first. Used by the alert detail's response-history audit
// drill-down (Phase 4 #76). limit caps the result set; values <= 0 or
// > 500 fall back to 100.
func (s *Store) ListAuditByTarget(ctx context.Context, kind, id string, limit int) ([]AuditRow, error) {
	if kind == "" || id == "" {
		return nil, fmt.Errorf("pg.ListAuditByTarget: kind + id required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, actor_type, COALESCE(actor_id, ''),
		       action, COALESCE(target_kind, ''), COALESCE(target_id, ''),
		       detail, created_at
		FROM audit_log
		WHERE target_kind = $1 AND target_id = $2
		ORDER BY id DESC
		LIMIT $3
	`, kind, id, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListAuditByTarget: %w", err)
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var (
			r       AuditRow
			rawJSON []byte
		)
		if err := rows.Scan(
			&r.ID, &r.ActorType, &r.ActorID,
			&r.Action, &r.TargetKind, &r.TargetID,
			&rawJSON, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("pg.ListAuditByTarget: scan: %w", err)
		}
		if len(rawJSON) > 0 {
			_ = json.Unmarshal(rawJSON, &r.Detail)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActorType matches the Postgres actor_type enum.
type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorSystem ActorType = "system"
	ActorAgent  ActorType = "agent"
)

// AuditEntry is one row-to-be in audit_log. TargetID / TargetKind may be
// empty when the action has no single target (e.g., a bulk operation).
// Detail is marshalled to jsonb.
type AuditEntry struct {
	ActorType  ActorType
	ActorID    string
	Action     string
	TargetKind string
	TargetID   string
	Detail     map[string]any
}

// LogAudit inserts one audit row. This path is best-effort in most
// callers — failing to write an audit record should NOT cause the
// primary action to fail — but it DOES return the error so callers can
// decide whether to surface it; the Enroll RPC, for example, logs the
// error and continues.
func (s *Store) LogAudit(ctx context.Context, entry AuditEntry) error {
	detail := []byte("{}")
	if entry.Detail != nil {
		b, err := json.Marshal(entry.Detail)
		if err != nil {
			return fmt.Errorf("pg.LogAudit: marshal detail: %w", err)
		}
		detail = b
	}
	var actorID any
	if entry.ActorID != "" {
		actorID = entry.ActorID
	}
	var targetKind any
	if entry.TargetKind != "" {
		targetKind = entry.TargetKind
	}
	var targetID any
	if entry.TargetID != "" {
		targetID = entry.TargetID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, target_kind, target_id, detail)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, string(entry.ActorType), actorID, entry.Action, targetKind, targetID, detail)
	if err != nil {
		return fmt.Errorf("pg.LogAudit: %w", err)
	}
	return nil
}
