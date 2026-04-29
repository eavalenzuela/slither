package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ResponseAction enumerates the six response action classes ADR-0034
// freezes. The strings match the CHECK on response_actions.action and
// the proto.ResponseAction enum names (sans the RESPONSE_ACTION_
// prefix).
type ResponseAction string

const (
	ResponseActionKillProcess      ResponseAction = "kill_process"
	ResponseActionKillTree         ResponseAction = "kill_tree"
	ResponseActionQuarantineFile   ResponseAction = "quarantine_file"
	ResponseActionIsolateHost      ResponseAction = "isolate_host"
	ResponseActionUnisolateHost    ResponseAction = "unisolate_host"
	ResponseActionCollectArtifacts ResponseAction = "collect_artifacts"
)

// ResponseStatus is the state-machine value for a response_actions row.
type ResponseStatus string

const (
	ResponseStatusPending        ResponseStatus = "pending"
	ResponseStatusRunning        ResponseStatus = "running"
	ResponseStatusDone           ResponseStatus = "done"
	ResponseStatusFailed         ResponseStatus = "failed"
	ResponseStatusDeniedByPolicy ResponseStatus = "denied_by_policy"
	ResponseStatusReverted       ResponseStatus = "reverted"
)

// ResponseActionInsert is the input shape for InsertResponseAction. At
// least one of OperatorID / RuleUID must be set — the CHECK on the
// table enforces "who asked?" but we surface the same invariant
// here so callers see a clean Go error rather than a pg constraint
// violation.
type ResponseActionInsert struct {
	AlertID       string         // UUID stringified; "" allowed (alert may be optional)
	HostID        string         // UUID; required
	Action        ResponseAction // required
	Target        string         // required (pid/path/host_id depending on Action)
	OperatorID    string         // empty for rule-driven
	RuleUID       string         // empty for operator-driven
	ParentAction  string         // empty for new actions; set for reversals
	ReasonCode    string         // optional human-readable label
	InitialStatus ResponseStatus // defaults to ResponseStatusPending
}

// ResponseActionRow projects the response_actions table for the
// console + dispatcher. Pointer fields distinguish "never set" from
// "set to zero value".
type ResponseActionRow struct {
	ID           string
	AlertID      string
	HostID       string
	Action       ResponseAction
	Target       string
	OperatorID   string
	RuleUID      string
	Status       ResponseStatus
	ReasonCode   string
	ResultBlob   []byte
	ParentAction string
	CreatedAt    time.Time
	StartedAt    *time.Time
	CompletedAt  *time.Time
}

// ErrResponseActionNotFound is returned when GetResponseAction or
// TransitionResponseAction can't find the row.
var ErrResponseActionNotFound = errors.New("pg: response action not found")

// ErrResponseInvalidTransition is returned by TransitionResponseAction
// when the requested next status is not legal from the current row's
// status. Same shape as ErrInvalidAlertTransition for consistency.
var ErrResponseInvalidTransition = errors.New("pg: invalid response status transition")

// InsertResponseAction lands a new row. Validates the "who asked?"
// invariant client-side; the CHECK on the table is the durable guard.
func (s *Store) InsertResponseAction(ctx context.Context, ins ResponseActionInsert) (ResponseActionRow, error) {
	if ins.HostID == "" {
		return ResponseActionRow{}, errors.New("pg.InsertResponseAction: host_id required")
	}
	if ins.Action == "" {
		return ResponseActionRow{}, errors.New("pg.InsertResponseAction: action required")
	}
	if ins.Target == "" {
		return ResponseActionRow{}, errors.New("pg.InsertResponseAction: target required")
	}
	if ins.OperatorID == "" && ins.RuleUID == "" {
		return ResponseActionRow{}, errors.New("pg.InsertResponseAction: one of operator_id / rule_uid required")
	}
	hostUUID, err := parseUUID(ins.HostID)
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.InsertResponseAction: parse host_id: %w", err)
	}

	var (
		alertUUID  pgtype.UUID
		opUUID     pgtype.UUID
		parentUUID pgtype.UUID
	)
	if ins.AlertID != "" {
		u, perr := parseUUID(ins.AlertID)
		if perr != nil {
			return ResponseActionRow{}, fmt.Errorf("pg.InsertResponseAction: parse alert_id: %w", perr)
		}
		alertUUID = u
	}
	if ins.OperatorID != "" {
		u, perr := parseUUID(ins.OperatorID)
		if perr != nil {
			return ResponseActionRow{}, fmt.Errorf("pg.InsertResponseAction: parse operator_id: %w", perr)
		}
		opUUID = u
	}
	if ins.ParentAction != "" {
		u, perr := parseUUID(ins.ParentAction)
		if perr != nil {
			return ResponseActionRow{}, fmt.Errorf("pg.InsertResponseAction: parse parent_action: %w", perr)
		}
		parentUUID = u
	}

	status := ins.InitialStatus
	if status == "" {
		status = ResponseStatusPending
	}

	var row ResponseActionRow
	err = s.pool.QueryRow(ctx, `
		INSERT INTO response_actions (
		    alert_id, host_id, action, target,
		    operator_id, rule_uid, status, reason_code, parent_action
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, NULLIF($8, ''), $9)
		RETURNING id, COALESCE(alert_id::text, ''), host_id::text,
		          action, target,
		          COALESCE(operator_id::text, ''), COALESCE(rule_uid, ''),
		          status, COALESCE(reason_code, ''), result_blob,
		          COALESCE(parent_action::text, ''),
		          created_at, started_at, completed_at
	`, alertUUID, hostUUID, string(ins.Action), ins.Target,
		opUUID, ins.RuleUID, string(status), ins.ReasonCode, parentUUID,
	).Scan(&row.ID, &row.AlertID, &row.HostID,
		&row.Action, &row.Target,
		&row.OperatorID, &row.RuleUID,
		&row.Status, &row.ReasonCode, &row.ResultBlob,
		&row.ParentAction,
		&row.CreatedAt, &row.StartedAt, &row.CompletedAt,
	)
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.InsertResponseAction: %w", err)
	}
	return row, nil
}

// ResponseActionTransition is the input shape for
// TransitionResponseAction. ResultBlob may be nil; ReasonCode replaces
// the existing reason_code only when non-empty.
type ResponseActionTransition struct {
	ActionID   string
	To         ResponseStatus
	Detail     string // surfaced as reason_code
	ResultBlob []byte
	ActorID    string // operator who initiated the transition (for audit)
}

// TransitionResponseAction advances a row's status. Validates the
// state-machine via IsValidResponseTransition. Sets started_at on
// `pending → running`; sets completed_at on any terminal status. Logs
// to audit_log with target_kind=response_action so forensics can pull
// the transition trail.
func (s *Store) TransitionResponseAction(ctx context.Context, t ResponseActionTransition) (ResponseActionRow, error) {
	if t.ActionID == "" {
		return ResponseActionRow{}, errors.New("pg.TransitionResponseAction: action_id required")
	}
	actionUUID, err := parseUUID(t.ActionID)
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: parse action_id: %w", err)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current ResponseStatus
	if err := tx.QueryRow(ctx,
		`SELECT status FROM response_actions WHERE id = $1 FOR UPDATE`,
		actionUUID,
	).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ResponseActionRow{}, ErrResponseActionNotFound
		}
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: lock: %w", err)
	}

	if !IsValidResponseTransition(current, t.To) {
		return ResponseActionRow{}, fmt.Errorf("%w: %s -> %s", ErrResponseInvalidTransition, current, t.To)
	}

	startedClause := ""
	completedClause := ""
	switch t.To {
	case ResponseStatusRunning:
		startedClause = ", started_at = COALESCE(started_at, now())"
	case ResponseStatusDone, ResponseStatusFailed, ResponseStatusDeniedByPolicy, ResponseStatusReverted:
		completedClause = ", completed_at = now()"
	}

	stmt := fmt.Sprintf(`
		UPDATE response_actions
		SET status = $2,
		    reason_code = COALESCE(NULLIF($3, ''), reason_code),
		    result_blob = COALESCE($4, result_blob)
		    %s%s
		WHERE id = $1
		RETURNING id, COALESCE(alert_id::text, ''), host_id::text,
		          action, target,
		          COALESCE(operator_id::text, ''), COALESCE(rule_uid, ''),
		          status, COALESCE(reason_code, ''), result_blob,
		          COALESCE(parent_action::text, ''),
		          created_at, started_at, completed_at
	`, startedClause, completedClause)

	var row ResponseActionRow
	if err := tx.QueryRow(ctx, stmt, actionUUID, string(t.To), t.Detail, t.ResultBlob).Scan(
		&row.ID, &row.AlertID, &row.HostID,
		&row.Action, &row.Target,
		&row.OperatorID, &row.RuleUID,
		&row.Status, &row.ReasonCode, &row.ResultBlob,
		&row.ParentAction,
		&row.CreatedAt, &row.StartedAt, &row.CompletedAt,
	); err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: update: %w", err)
	}

	// Log within the same transaction so the audit row + the state
	// transition land atomically. Detail captures prev → next + the
	// optional message + result-blob length so forensics see what
	// happened without dragging the blob into audit_log.
	auditDetail := map[string]any{
		"prev_status":      string(current),
		"next_status":      string(t.To),
		"detail":           t.Detail,
		"result_blob_size": len(t.ResultBlob),
	}
	auditJSON, _ := json.Marshal(auditDetail)
	// Edge auto-respond + system-driven transitions arrive with empty
	// ActorID; audit_log distinguishes them via actor_type (set below
	// in actorTypeFor). User-driven transitions arrive with ActorID set
	// to the operator's users.id.
	actor := t.ActorID
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, target_kind, target_id, detail)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6::jsonb)
	`,
		actorTypeFor(actor),
		actor,
		"response.action.transition",
		"response_action",
		row.ID,
		auditJSON,
	); err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: audit: %w", err)
	}

	if t.To == ResponseStatusDone && row.ParentAction != "" {
		// Mark the parent reverted iff the reverse just succeeded.
		// IsValidResponseTransition guards the parent's own state;
		// this only fires when the parent is still in a non-terminal
		// state. Use the same actor + a chained audit row so the
		// reversal trail is complete.
		parentUUID, _ := parseUUID(row.ParentAction)
		var parentStatus ResponseStatus
		if err := tx.QueryRow(ctx,
			`SELECT status FROM response_actions WHERE id = $1 FOR UPDATE`,
			parentUUID,
		).Scan(&parentStatus); err == nil && IsValidResponseTransition(parentStatus, ResponseStatusReverted) {
			if _, err := tx.Exec(ctx, `
				UPDATE response_actions
				SET status = 'reverted', completed_at = COALESCE(completed_at, now())
				WHERE id = $1
			`, parentUUID); err != nil {
				return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: revert parent: %w", err)
			}
			parentDetail := map[string]any{
				"prev_status": string(parentStatus),
				"next_status": string(ResponseStatusReverted),
				"reverted_by": row.ID,
			}
			parentJSON, _ := json.Marshal(parentDetail)
			if _, err := tx.Exec(ctx, `
				INSERT INTO audit_log (actor_type, actor_id, action, target_kind, target_id, detail)
				VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6::jsonb)
			`,
				actorTypeFor(actor), actor,
				"response.action.reverted",
				"response_action",
				row.ParentAction,
				parentJSON,
			); err != nil {
				return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: audit revert: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.TransitionResponseAction: commit: %w", err)
	}
	return row, nil
}

// IsValidResponseTransition implements the state-machine ADR-0034 cites:
//
//	pending → running, denied_by_policy
//	running → done, failed
//	done    → reverted (only when a child action with parent_action=this completes)
//	failed, denied_by_policy, reverted are terminal
//
// done → reverted is intentionally allowed only via the parent flip in
// TransitionResponseAction; callers transitioning by hand to reverted
// are rejected to keep the chain consistent.
func IsValidResponseTransition(from, to ResponseStatus) bool {
	if from == to {
		return false
	}
	switch from {
	case ResponseStatusPending:
		return to == ResponseStatusRunning ||
			to == ResponseStatusDeniedByPolicy ||
			to == ResponseStatusFailed
	case ResponseStatusRunning:
		return to == ResponseStatusDone || to == ResponseStatusFailed
	case ResponseStatusDone:
		return to == ResponseStatusReverted
	}
	return false
}

// GetResponseAction returns one row by id.
func (s *Store) GetResponseAction(ctx context.Context, id string) (ResponseActionRow, error) {
	actionUUID, err := parseUUID(id)
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.GetResponseAction: parse id: %w", err)
	}
	var row ResponseActionRow
	err = s.pool.QueryRow(ctx, `
		SELECT id, COALESCE(alert_id::text, ''), host_id::text,
		       action, target,
		       COALESCE(operator_id::text, ''), COALESCE(rule_uid, ''),
		       status, COALESCE(reason_code, ''), result_blob,
		       COALESCE(parent_action::text, ''),
		       created_at, started_at, completed_at
		FROM response_actions
		WHERE id = $1
	`, actionUUID).Scan(
		&row.ID, &row.AlertID, &row.HostID,
		&row.Action, &row.Target,
		&row.OperatorID, &row.RuleUID,
		&row.Status, &row.ReasonCode, &row.ResultBlob,
		&row.ParentAction,
		&row.CreatedAt, &row.StartedAt, &row.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResponseActionRow{}, ErrResponseActionNotFound
	}
	if err != nil {
		return ResponseActionRow{}, fmt.Errorf("pg.GetResponseAction: %w", err)
	}
	return row, nil
}

// ListResponseActions returns every action against hostID, newest
// first. Used by the alert detail's "action history" pane.
func (s *Store) ListResponseActions(ctx context.Context, hostID string, limit int) ([]ResponseActionRow, error) {
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListResponseActions: parse host_id: %w", err)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(alert_id::text, ''), host_id::text,
		       action, target,
		       COALESCE(operator_id::text, ''), COALESCE(rule_uid, ''),
		       status, COALESCE(reason_code, ''), result_blob,
		       COALESCE(parent_action::text, ''),
		       created_at, started_at, completed_at
		FROM response_actions
		WHERE host_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, hostUUID, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListResponseActions: query: %w", err)
	}
	defer rows.Close()
	var out []ResponseActionRow
	for rows.Next() {
		var r ResponseActionRow
		if err := rows.Scan(
			&r.ID, &r.AlertID, &r.HostID,
			&r.Action, &r.Target,
			&r.OperatorID, &r.RuleUID,
			&r.Status, &r.ReasonCode, &r.ResultBlob,
			&r.ParentAction,
			&r.CreatedAt, &r.StartedAt, &r.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("pg.ListResponseActions: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HostPolicy is the per-host response policy (ADR-0034). Default value
// (all-false) is the "detect-only" baseline for fresh enrolments.
type HostPolicy struct {
	HostID           string
	AllowKillProcess bool
	AllowKillTree    bool
	AllowQuarantine  bool
	AllowIsolate     bool
	AllowCollect     bool
	UpdatedAt        time.Time
	UpdatedBy        string // user id; empty when system-set
}

// PermitsAction reports whether the policy allows the given action.
// Reverse actions inherit their parent's permission per ADR-0034 — the
// dispatcher checks AllowIsolate for both ISOLATE_HOST and
// UNISOLATE_HOST.
func (p HostPolicy) PermitsAction(a ResponseAction) bool {
	switch a {
	case ResponseActionKillProcess:
		return p.AllowKillProcess
	case ResponseActionKillTree:
		return p.AllowKillTree
	case ResponseActionQuarantineFile:
		return p.AllowQuarantine
	case ResponseActionIsolateHost, ResponseActionUnisolateHost:
		return p.AllowIsolate
	case ResponseActionCollectArtifacts:
		return p.AllowCollect
	}
	return false
}

// GetHostPolicy returns the policy row for hostID. A missing row
// resolves to the all-false baseline (detect-only) — fresh hosts are
// safe by default.
func (s *Store) GetHostPolicy(ctx context.Context, hostID string) (HostPolicy, error) {
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return HostPolicy{}, fmt.Errorf("pg.GetHostPolicy: parse host_id: %w", err)
	}
	var (
		p         HostPolicy
		updatedBy pgtype.UUID
	)
	err = s.pool.QueryRow(ctx, `
		SELECT host_id::text, allow_kill_process, allow_kill_tree,
		       allow_quarantine, allow_isolate, allow_collect,
		       updated_at, updated_by
		FROM host_response_policies
		WHERE host_id = $1
	`, hostUUID).Scan(
		&p.HostID, &p.AllowKillProcess, &p.AllowKillTree,
		&p.AllowQuarantine, &p.AllowIsolate, &p.AllowCollect,
		&p.UpdatedAt, &updatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostPolicy{HostID: hostID}, nil
	}
	if err != nil {
		return HostPolicy{}, fmt.Errorf("pg.GetHostPolicy: %w", err)
	}
	if updatedBy.Valid {
		p.UpdatedBy = uuidString(updatedBy)
	}
	return p, nil
}

// ListHostPolicies returns one row per host (including a synthetic
// all-false row for hosts without an explicit policy entry). Used by
// the admin /hosts page when enabling response on a host.
func (s *Store) ListHostPolicies(ctx context.Context) ([]HostPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.id::text,
		       COALESCE(p.allow_kill_process, false),
		       COALESCE(p.allow_kill_tree,    false),
		       COALESCE(p.allow_quarantine,   false),
		       COALESCE(p.allow_isolate,      false),
		       COALESCE(p.allow_collect,      false),
		       COALESCE(p.updated_at, h.enrolled_at),
		       p.updated_by
		FROM hosts h
		LEFT JOIN host_response_policies p ON p.host_id = h.id
		ORDER BY h.hostname, h.id
	`)
	if err != nil {
		return nil, fmt.Errorf("pg.ListHostPolicies: %w", err)
	}
	defer rows.Close()
	var out []HostPolicy
	for rows.Next() {
		var (
			p         HostPolicy
			updatedBy pgtype.UUID
		)
		if err := rows.Scan(
			&p.HostID, &p.AllowKillProcess, &p.AllowKillTree,
			&p.AllowQuarantine, &p.AllowIsolate, &p.AllowCollect,
			&p.UpdatedAt, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("pg.ListHostPolicies: scan: %w", err)
		}
		if updatedBy.Valid {
			p.UpdatedBy = uuidString(updatedBy)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertHostPolicy writes a policy row for hostID, replacing the
// existing one if any. updatedBy is the operator who initiated the
// edit (audited via audit_log inside the same transaction).
func (s *Store) UpsertHostPolicy(ctx context.Context, p HostPolicy, updatedBy string) (HostPolicy, error) {
	if p.HostID == "" {
		return HostPolicy{}, errors.New("pg.UpsertHostPolicy: host_id required")
	}
	hostUUID, err := parseUUID(p.HostID)
	if err != nil {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: parse host_id: %w", err)
	}
	var actor pgtype.UUID
	if updatedBy != "" {
		u, perr := parseUUID(updatedBy)
		if perr != nil {
			return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: parse updated_by: %w", perr)
		}
		actor = u
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var prev HostPolicy
	prevErr := tx.QueryRow(ctx, `
		SELECT host_id::text, allow_kill_process, allow_kill_tree,
		       allow_quarantine, allow_isolate, allow_collect,
		       updated_at
		FROM host_response_policies
		WHERE host_id = $1
		FOR UPDATE
	`, hostUUID).Scan(
		&prev.HostID, &prev.AllowKillProcess, &prev.AllowKillTree,
		&prev.AllowQuarantine, &prev.AllowIsolate, &prev.AllowCollect,
		&prev.UpdatedAt,
	)
	if prevErr != nil && !errors.Is(prevErr, pgx.ErrNoRows) {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: lock: %w", prevErr)
	}

	var (
		updated  HostPolicy
		updByOut pgtype.UUID
	)
	if err := tx.QueryRow(ctx, `
		INSERT INTO host_response_policies (
		    host_id, allow_kill_process, allow_kill_tree,
		    allow_quarantine, allow_isolate, allow_collect,
		    updated_at, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, now(), $7)
		ON CONFLICT (host_id) DO UPDATE SET
		    allow_kill_process = EXCLUDED.allow_kill_process,
		    allow_kill_tree    = EXCLUDED.allow_kill_tree,
		    allow_quarantine   = EXCLUDED.allow_quarantine,
		    allow_isolate      = EXCLUDED.allow_isolate,
		    allow_collect      = EXCLUDED.allow_collect,
		    updated_at         = now(),
		    updated_by         = EXCLUDED.updated_by
		RETURNING host_id::text, allow_kill_process, allow_kill_tree,
		          allow_quarantine, allow_isolate, allow_collect,
		          updated_at, updated_by
	`,
		hostUUID,
		p.AllowKillProcess, p.AllowKillTree,
		p.AllowQuarantine, p.AllowIsolate, p.AllowCollect,
		actor,
	).Scan(
		&updated.HostID, &updated.AllowKillProcess, &updated.AllowKillTree,
		&updated.AllowQuarantine, &updated.AllowIsolate, &updated.AllowCollect,
		&updated.UpdatedAt, &updByOut,
	); err != nil {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: %w", err)
	}
	if updByOut.Valid {
		updated.UpdatedBy = uuidString(updByOut)
	}

	auditDetail := map[string]any{
		"prev": prev,
		"next": updated,
	}
	auditJSON, _ := json.Marshal(auditDetail)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, target_kind, target_id, detail)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6::jsonb)
	`,
		actorTypeFor(updatedBy), updatedBy,
		"host.response_policy.upsert",
		"host", p.HostID,
		auditJSON,
	); err != nil {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: audit: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return HostPolicy{}, fmt.Errorf("pg.UpsertHostPolicy: commit: %w", err)
	}
	return updated, nil
}

// WatchHostPolicies opens a dedicated LISTEN connection and emits a
// signal on the returned channel every time a host_response_policies
// row changes. Mirrors WatchRules from #39 — payload is empty; the
// channel itself is the event signal so handlers re-read the table to
// pick up the new state. Channel closes when ctx is cancelled.
func (s *Store) WatchHostPolicies(ctx context.Context) (<-chan struct{}, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pg.WatchHostPolicies: acquire: %w", err)
	}
	if _, err := conn.Exec(ctx, `LISTEN host_response_policies_changed`); err != nil {
		conn.Release()
		return nil, fmt.Errorf("pg.WatchHostPolicies: listen: %w", err)
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		defer conn.Release()
		for {
			if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
				return
			}
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out, nil
}

// actorTypeFor picks the right ActorType for an audit row given the
// caller's actor id. Empty id => system; otherwise user. Edge auto-
// respond will eventually want ActorAgent; callers passing the agent's
// host id should use LogAudit directly.
func actorTypeFor(actorID string) string {
	if actorID == "" {
		return string(ActorSystem)
	}
	return string(ActorUser)
}
