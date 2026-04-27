package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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

// AlertStatus mirrors the Postgres alert_status enum from migration
// 00006. The vocabulary is fixed by the CHECK on alerts; new values
// require a migration.
type AlertStatus string

const (
	AlertNew          AlertStatus = "new"
	AlertAcknowledged AlertStatus = "acknowledged"
	AlertInProgress   AlertStatus = "in_progress"
	AlertClosed       AlertStatus = "closed"
)

// AlertRow projects the alerts table for the operator console. Rule
// metadata is joined opportunistically — rule_uid is text-not-FK so a
// deleted rule still surfaces an alert with its stored uid.
type AlertRow struct {
	ID         string
	RuleUID    string
	RuleName   string // empty when the rule was deleted
	HostID     string
	Hostname   string // empty when the host row is gone (host CASCADE delete)
	EventIDs   []string
	Severity   uint8
	Status     AlertStatus
	ReasonCode string
	AssignedTo string // user_id or empty
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ClosedAt   *time.Time
}

// AlertFilter narrows ListAlerts. Empty fields mean "no constraint";
// Statuses == nil means every status (open + closed both surface).
type AlertFilter struct {
	Statuses   []AlertStatus
	HostID     string
	RuleUID    string
	SeverityID uint8 // 0 = no constraint
}

// AlertCursor is the opaque pagination key for ListAlerts. Zero value
// means "first page". Same shape as ch.Cursor — RFC3339Nano +
// alert_id keeps it human-debuggable.
type AlertCursor struct {
	CreatedAt time.Time
	AlertID   string
}

// ListAlerts returns up to limit rows matching filter, ordered by
// (created_at DESC, id DESC). When more rows likely exist past the
// returned page, nextCursor is non-zero and ready to feed back as
// the cursor argument on the next page request.
func (s *Store) ListAlerts(ctx context.Context, filter AlertFilter, cursor AlertCursor, limit int) (rows []AlertRow, nextCursor AlertCursor, err error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	clauses := []string{}
	args := []any{}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if len(filter.Statuses) > 0 {
		ph := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			ph[i] = add(string(st))
		}
		clauses = append(clauses, fmt.Sprintf("a.status IN (%s)", strings.Join(ph, ",")))
	}
	if filter.HostID != "" {
		hostUUID, perr := uuid.Parse(filter.HostID)
		if perr != nil {
			return nil, AlertCursor{}, fmt.Errorf("pg.ListAlerts: parse host_id: %w", perr)
		}
		clauses = append(clauses, fmt.Sprintf("a.host_id = %s", add(hostUUID)))
	}
	if filter.RuleUID != "" {
		clauses = append(clauses, fmt.Sprintf("a.rule_uid = %s", add(filter.RuleUID)))
	}
	if filter.SeverityID != 0 {
		clauses = append(clauses, fmt.Sprintf("a.severity = %s", add(int16(filter.SeverityID))))
	}
	if cursor.AlertID != "" {
		alertUUID, perr := uuid.Parse(cursor.AlertID)
		if perr != nil {
			return nil, AlertCursor{}, fmt.Errorf("pg.ListAlerts: parse cursor id: %w", perr)
		}
		ts1 := add(cursor.CreatedAt)
		ts2 := add(cursor.CreatedAt)
		idArg := add(alertUUID)
		clauses = append(clauses, fmt.Sprintf(
			"(a.created_at < %s OR (a.created_at = %s AND a.id < %s))",
			ts1, ts2, idArg))
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	stmt := fmt.Sprintf(`
		SELECT a.id, a.rule_uid, COALESCE(r.name, '') AS rule_name,
		       a.host_id, COALESCE(h.hostname, '') AS hostname,
		       a.event_ids, a.severity, a.status,
		       COALESCE(a.reason_code, '') AS reason_code,
		       COALESCE(a.assigned_to::text, '') AS assigned_to,
		       a.created_at, a.updated_at, a.closed_at
		FROM alerts a
		LEFT JOIN rules r ON r.uid = a.rule_uid
		LEFT JOIN hosts h ON h.id  = a.host_id
		%s
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT %d
	`, where, limit+1)

	queried, err := s.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, AlertCursor{}, fmt.Errorf("pg.ListAlerts: query: %w", err)
	}
	defer queried.Close()

	out := make([]AlertRow, 0, limit+1)
	for queried.Next() {
		var (
			row        AlertRow
			eventUUIDs []uuid.UUID
			alertID    uuid.UUID
			hostID     uuid.UUID
			closedAt   *time.Time
			status     string
		)
		if err := queried.Scan(
			&alertID, &row.RuleUID, &row.RuleName,
			&hostID, &row.Hostname,
			&eventUUIDs, &row.Severity, &status,
			&row.ReasonCode, &row.AssignedTo,
			&row.CreatedAt, &row.UpdatedAt, &closedAt,
		); err != nil {
			return nil, AlertCursor{}, fmt.Errorf("pg.ListAlerts: scan: %w", err)
		}
		row.ID = alertID.String()
		row.HostID = hostID.String()
		row.Status = AlertStatus(status)
		if closedAt != nil {
			row.ClosedAt = closedAt
		}
		row.EventIDs = make([]string, len(eventUUIDs))
		for i, u := range eventUUIDs {
			row.EventIDs[i] = u.String()
		}
		out = append(out, row)
	}
	if err := queried.Err(); err != nil {
		return nil, AlertCursor{}, fmt.Errorf("pg.ListAlerts: iter: %w", err)
	}

	if len(out) > limit {
		nc := AlertCursor{
			CreatedAt: out[limit-1].CreatedAt,
			AlertID:   out[limit-1].ID,
		}
		return out[:limit], nc, nil
	}
	return out, AlertCursor{}, nil
}

// GetAlert returns one row by id. Returns ErrAlertNotFound when the
// row is missing so callers can map to 404 without string-matching.
func (s *Store) GetAlert(ctx context.Context, id string) (AlertRow, error) {
	alertUUID, err := uuid.Parse(id)
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.GetAlert: parse id: %w", err)
	}
	var (
		row        AlertRow
		eventUUIDs []uuid.UUID
		hostID     uuid.UUID
		closedAt   *time.Time
		status     string
	)
	err = s.pool.QueryRow(ctx, `
		SELECT a.rule_uid, COALESCE(r.name, ''),
		       a.host_id, COALESCE(h.hostname, ''),
		       a.event_ids, a.severity, a.status,
		       COALESCE(a.reason_code, ''),
		       COALESCE(a.assigned_to::text, ''),
		       a.created_at, a.updated_at, a.closed_at
		FROM alerts a
		LEFT JOIN rules r ON r.uid = a.rule_uid
		LEFT JOIN hosts h ON h.id  = a.host_id
		WHERE a.id = $1
	`, alertUUID).Scan(
		&row.RuleUID, &row.RuleName,
		&hostID, &row.Hostname,
		&eventUUIDs, &row.Severity, &status,
		&row.ReasonCode, &row.AssignedTo,
		&row.CreatedAt, &row.UpdatedAt, &closedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AlertRow{}, ErrAlertNotFound
	}
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.GetAlert: %w", err)
	}
	row.ID = id
	row.HostID = hostID.String()
	row.Status = AlertStatus(status)
	if closedAt != nil {
		row.ClosedAt = closedAt
	}
	row.EventIDs = make([]string, len(eventUUIDs))
	for i, u := range eventUUIDs {
		row.EventIDs[i] = u.String()
	}
	return row, nil
}

// ErrAlertNotFound is returned by GetAlert / TransitionAlert when the
// alert id is missing.
var ErrAlertNotFound = errors.New("pg: alert not found")

// ErrInvalidTransition is returned by TransitionAlert when the
// requested target status isn't reachable from the alert's current
// status.
var ErrInvalidTransition = errors.New("pg: invalid alert transition")

// validTransitions table — keep aligned with PROJECT.md §5 lifecycle.
// Closed alerts are terminal in v1; reopening waits for Phase 5.
var validAlertTransitions = map[AlertStatus]map[AlertStatus]bool{
	AlertNew: {
		AlertAcknowledged: true,
		AlertInProgress:   true, // skip the ack step — common in real intake flows
		AlertClosed:       true, // quick-close from intake
	},
	AlertAcknowledged: {
		AlertInProgress: true,
		AlertClosed:     true,
	},
	AlertInProgress: {
		AlertClosed: true,
	},
}

// IsValidAlertTransition is the predicate the console + tests share.
// Same source as the SQL CASE in TransitionAlert; pure function so
// view-side rendering can decide button visibility without a round
// trip.
func IsValidAlertTransition(from, to AlertStatus) bool {
	if from == to {
		return false
	}
	allowed, ok := validAlertTransitions[from]
	if !ok {
		return false
	}
	return allowed[to]
}

// AlertTransition is the input to TransitionAlert. Reason is the
// optional human-readable label stamped onto reason_code (and into
// the audit row's detail). Actor is the user_id of the operator
// performing the transition; required so audit_log captures who.
type AlertTransition struct {
	AlertID string
	To      AlertStatus
	Reason  string
	Actor   string
}

// TransitionAlert atomically advances an alert's status. The update
// uses an expected-status guard (WHERE status = current) so a
// concurrent ack from a second analyst doesn't double-fire the
// transition; ErrInvalidTransition is returned in that case so the
// caller can show a "someone else got there first" message rather
// than silently no-op.
//
// Closed transitions stamp closed_at = now(); the alerts CHECK on
// (status = 'closed') = (closed_at IS NOT NULL) requires the two
// columns to move in lockstep. Audit logging is best-effort within
// the same transaction so an audit-failure rolls the transition
// back.
func (s *Store) TransitionAlert(ctx context.Context, t AlertTransition) (AlertRow, error) {
	alertUUID, err := uuid.Parse(t.AlertID)
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: parse id: %w", err)
	}
	if t.To == "" {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: target status required")
	}
	if t.Actor == "" {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: actor required")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current string
	if scanErr := tx.QueryRow(ctx, `
		SELECT status FROM alerts WHERE id = $1 FOR UPDATE
	`, alertUUID).Scan(&current); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return AlertRow{}, ErrAlertNotFound
		}
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: select: %w", scanErr)
	}

	from := AlertStatus(current)
	if !IsValidAlertTransition(from, t.To) {
		return AlertRow{}, ErrInvalidTransition
	}

	closedSet := "NULL"
	if t.To == AlertClosed {
		closedSet = "now()"
	}
	stmt := fmt.Sprintf(`
		UPDATE alerts
		   SET status      = $2,
		       reason_code = COALESCE(NULLIF($3, ''), reason_code),
		       updated_at  = now(),
		       closed_at   = %s
		 WHERE id = $1 AND status = $4
	`, closedSet)
	tag, err := tx.Exec(ctx, stmt, alertUUID, string(t.To), t.Reason, current)
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Concurrent transition between SELECT FOR UPDATE and UPDATE
		// shouldn't happen with the row lock, but keep the guard so a
		// future schema change (e.g. dropping FOR UPDATE) doesn't
		// silently misbehave.
		return AlertRow{}, ErrInvalidTransition
	}

	actorUUID, err := uuid.Parse(t.Actor)
	if err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: parse actor: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{
		"from":   string(from),
		"to":     string(t.To),
		"reason": t.Reason,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, target_kind, target_id, detail)
		VALUES ('user', $1, $2, 'alert', $3, $4)
	`,
		actorUUID,
		fmt.Sprintf("alert.transition.%s_%s", from, t.To),
		alertUUID.String(),
		detail,
	); err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AlertRow{}, fmt.Errorf("pg.TransitionAlert: commit: %w", err)
	}

	// Re-read to return the post-transition row to the caller. Cheap
	// — happens once per operator click, not per event.
	return s.GetAlert(ctx, t.AlertID)
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
