package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AlertInsert is the minimal projection an alert sink (#60) needs to
// land a row in the alerts table. event_ids may be empty; severity
// follows the OCSF severity_id 1..6 vocabulary the alerts table CHECK
// constraint enforces.
type AlertInsert struct {
	RuleUID    string
	HostID     string // UUID stringified — InsertAlert parses it back
	EventIDs   []string
	Severity   uint8
	ReasonCode string // optional human-readable label
}

// AlertInsertResult reports the outcome of InsertAlert. Inserted is
// false when per-rule dedupe (rules.dedupe_window_secs) suppressed
// the row; in that case AlertID is the zero UUID and DedupeWindowSecs
// carries the active window so callers can log the suppression.
type AlertInsertResult struct {
	Inserted         bool
	AlertID          uuid.UUID
	DedupeWindowSecs int
	DedupeSuppressed bool
}

// InsertAlert lands one Finding into the alerts table, applying the
// per-rule dedupe policy. When `rules.dedupe_window_secs` is set for
// the rule_uid, a SELECT inside the same transaction looks for a
// recent alert with matching (rule_uid, host_id, created_at >
// now() - window); if one exists, the new finding is suppressed and
// AlertInsertResult.DedupeSuppressed is true. Rules with no row in
// the rules table (the rule was deleted but the agent kept firing on
// a stale push) take the no-dedupe path — losing dedupe state for an
// orphan rule is the lesser evil compared with dropping the alert.
//
// rule_uid is a text column, not a FK to rules(uid), so deleting a
// rule never cascades away its alert history.
func (s *Store) InsertAlert(ctx context.Context, ins AlertInsert) (AlertInsertResult, error) {
	if ins.RuleUID == "" {
		return AlertInsertResult{}, errors.New("pg.InsertAlert: rule_uid required")
	}
	hostUUID, err := parseUUID(ins.HostID)
	if err != nil {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: parse host_id: %w", err)
	}
	if ins.Severity < 1 || ins.Severity > 6 {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: severity %d out of range 1..6", ins.Severity)
	}

	eventUUIDs := make([]uuid.UUID, 0, len(ins.EventIDs))
	for _, raw := range ins.EventIDs {
		if raw == "" {
			continue
		}
		u, perr := uuid.Parse(raw)
		if perr != nil {
			// One bad event id shouldn't block the alert — operators
			// still want to see the row. Log via the store's caller;
			// here we just skip the malformed entry.
			continue
		}
		eventUUIDs = append(eventUUIDs, u)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var dedupeSecs *int
	if err := tx.QueryRow(ctx, `
		SELECT dedupe_window_secs FROM rules WHERE uid = $1
	`, ins.RuleUID).Scan(&dedupeSecs); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: lookup dedupe: %w", err)
	}

	if dedupeSecs != nil {
		var existing int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM alerts
			WHERE rule_uid = $1
			  AND host_id  = $2
			  AND created_at > now() - make_interval(secs => $3::int)
		`, ins.RuleUID, hostUUID, *dedupeSecs).Scan(&existing); err != nil {
			return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: dedupe probe: %w", err)
		}
		if existing > 0 {
			if err := tx.Commit(ctx); err != nil {
				return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: commit (dedupe path): %w", err)
			}
			return AlertInsertResult{
				DedupeWindowSecs: *dedupeSecs,
				DedupeSuppressed: true,
			}, nil
		}
	}

	var alertID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO alerts (rule_uid, host_id, event_ids, severity, reason_code)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))
		RETURNING id
	`, ins.RuleUID, hostUUID, eventUUIDs, int16(ins.Severity), ins.ReasonCode).Scan(&alertID); err != nil {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AlertInsertResult{}, fmt.Errorf("pg.InsertAlert: commit: %w", err)
	}
	res := AlertInsertResult{
		Inserted: true,
		AlertID:  alertID,
	}
	if dedupeSecs != nil {
		res.DedupeWindowSecs = *dedupeSecs
	}
	return res, nil
}

// SetRuleDedupeWindow configures rules.dedupe_window_secs for a rule
// uid. seconds<=0 clears the window (NULL — no dedupe); positive
// values set the window. Caller is responsible for audit logging.
func (s *Store) SetRuleDedupeWindow(ctx context.Context, uid string, seconds int) error {
	var arg any
	if seconds > 0 {
		arg = seconds
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE rules SET dedupe_window_secs = $2, updated_at = now() WHERE uid = $1
	`, uid, arg)
	if err != nil {
		return fmt.Errorf("pg.SetRuleDedupeWindow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("pg.SetRuleDedupeWindow: rule %q not found", uid)
	}
	return nil
}
