package pg

import (
	"context"
	"encoding/json"
	"fmt"
)

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
