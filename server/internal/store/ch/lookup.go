package ch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EventNode is a class-tagged projection used by the alert flow-graph
// builder (#64). Class-specific hot-path columns are included so the
// builder can label nodes and chase causality (parent_pid for
// processes, actor_pid for file/net) without re-querying the raw JSON.
type EventNode struct {
	EventID    string
	HostID     string
	ClassUID   uint32
	ObservedAt time.Time

	// Process-only.
	PID       uint32
	ParentPID uint32
	ExecPath  string
	ProcName  string
	Cmdline   string

	// File-only.
	FilePath  string
	ActorName string

	// Network-only.
	Protocol string
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16

	// Detection-only / shared with file+net actor lookup.
	ActorPID uint32

	// Detection-only.
	RuleUID  string
	RuleName string
}

// GetEventNode looks up a single event across every class table. Class
// is auto-detected — alerts.event_ids[] does not carry class_uid, and
// the alert renderer needs the row regardless of class.
//
// Returns an error wrapping ErrEventNotFound when no class table holds
// the id.
func (s *Store) GetEventNode(ctx context.Context, eventID string) (EventNode, error) {
	eventUUID, err := uuid.Parse(eventID)
	if err != nil {
		return EventNode{}, fmt.Errorf("ch.GetEventNode: parse event_id: %w", err)
	}
	for classUID, table := range classTables {
		row, ok, err := s.lookupByEventID(ctx, classUID, table, eventUUID)
		if err != nil {
			return EventNode{}, fmt.Errorf("ch.GetEventNode: %s: %w", table, err)
		}
		if ok {
			return row, nil
		}
	}
	return EventNode{}, ErrEventNotFound
}

// LookupProcessByPID returns the most recent process_activity row for
// (host_id, pid) at or before observedBefore. Used by the flow-graph
// builder to chase parent processes (parent_pid lookup) and to find
// the actor process for file/network events. Time-window-bounded so a
// PID that was reused on the same host years later doesn't get
// returned.
//
// Returns ErrEventNotFound when no matching row is in the lookback
// window.
func (s *Store) LookupProcessByPID(
	ctx context.Context,
	hostID string,
	pid uint32,
	observedBefore time.Time,
	lookback time.Duration,
) (EventNode, error) {
	if pid == 0 {
		return EventNode{}, ErrEventNotFound
	}
	hostUUID, err := uuid.Parse(hostID)
	if err != nil {
		return EventNode{}, fmt.Errorf("ch.LookupProcessByPID: parse host_id: %w", err)
	}
	if lookback <= 0 {
		lookback = time.Hour
	}

	stmt := `
		SELECT
			toString(event_id), toString(host_id), class_uid, observed_at,
			pid, parent_pid, exec_path, process_name, cmdline
		FROM ocsf_process_activity_1007
		WHERE host_id = ?
		  AND pid     = ?
		  AND observed_at >= fromUnixTimestamp64Nano(?)
		  AND observed_at <= fromUnixTimestamp64Nano(?)
		ORDER BY observed_at DESC
		LIMIT 1
	`
	since := observedBefore.Add(-lookback).UnixNano()
	until := observedBefore.UnixNano()
	row := s.conn.QueryRow(ctx, stmt, hostUUID, pid, since, until)

	var n EventNode
	if err := row.Scan(
		&n.EventID, &n.HostID, &n.ClassUID, &n.ObservedAt,
		&n.PID, &n.ParentPID, &n.ExecPath, &n.ProcName, &n.Cmdline,
	); err != nil {
		if isNoRows(err) {
			return EventNode{}, ErrEventNotFound
		}
		return EventNode{}, fmt.Errorf("ch.LookupProcessByPID: scan: %w", err)
	}
	return n, nil
}

func (s *Store) lookupByEventID(ctx context.Context, classUID uint32, table string, eventUUID uuid.UUID) (EventNode, bool, error) {
	stmt := fmt.Sprintf(`
		SELECT %s
		FROM %s
		WHERE event_id = ?
		LIMIT 1
	`, classProjection(table), table)

	row := s.conn.QueryRow(ctx, stmt, eventUUID)

	n := EventNode{ClassUID: classUID}
	switch table {
	case "ocsf_process_activity_1007":
		err := row.Scan(
			&n.EventID, &n.HostID, &n.ObservedAt,
			&n.PID, &n.ParentPID, &n.ExecPath, &n.ProcName, &n.Cmdline,
		)
		if isNoRows(err) {
			return EventNode{}, false, nil
		}
		if err != nil {
			return EventNode{}, false, err
		}
	case "ocsf_file_system_activity_1001":
		err := row.Scan(
			&n.EventID, &n.HostID, &n.ObservedAt,
			&n.FilePath, &n.ActorPID, &n.ActorName,
		)
		if isNoRows(err) {
			return EventNode{}, false, nil
		}
		if err != nil {
			return EventNode{}, false, err
		}
	case "ocsf_network_activity_4001":
		err := row.Scan(
			&n.EventID, &n.HostID, &n.ObservedAt,
			&n.Protocol, &n.SrcIP, &n.SrcPort, &n.DstIP, &n.DstPort,
			&n.ActorPID, &n.ActorName,
		)
		if isNoRows(err) {
			return EventNode{}, false, nil
		}
		if err != nil {
			return EventNode{}, false, err
		}
	case "ocsf_detection_finding_2004":
		err := row.Scan(
			&n.EventID, &n.HostID, &n.ObservedAt,
			&n.RuleUID, &n.RuleName,
		)
		if isNoRows(err) {
			return EventNode{}, false, nil
		}
		if err != nil {
			return EventNode{}, false, err
		}
	default:
		return EventNode{}, false, fmt.Errorf("classProjection: unsupported table %q", table)
	}
	return n, true, nil
}

func classProjection(table string) string {
	switch table {
	case "ocsf_process_activity_1007":
		return `toString(event_id), toString(host_id), observed_at,
			pid, parent_pid, exec_path, process_name, cmdline`
	case "ocsf_file_system_activity_1001":
		return `toString(event_id), toString(host_id), observed_at,
			file_path, actor_pid, actor_name`
	case "ocsf_network_activity_4001":
		return `toString(event_id), toString(host_id), observed_at,
			protocol, src_ip, src_port, dst_ip, dst_port, actor_pid, actor_name`
	case "ocsf_detection_finding_2004":
		// Detection findings store rule metadata as columns in the
		// CH writer (#39). The list summary projection uses these
		// directly; the JSON in raw is the source of truth.
		return `toString(event_id), toString(host_id), observed_at,
			rule_uid, rule_name`
	}
	return ""
}

// ErrEventNotFound signals the queried event id is not present in any
// class table.
var ErrEventNotFound = errors.New("ch: event not found")

// isNoRows tests for the clickhouse-go "no rows" sentinel without
// importing database/sql at every call site.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	// clickhouse-go's QueryRow surfaces a sentinel rather than
	// sql.ErrNoRows when the result set is empty; the sentinel's
	// string form is stable enough to match on, and the alternative
	// (driver internals) crosses a bigger blast-radius boundary.
	return err.Error() == "sql: no rows in result set" ||
		err.Error() == "clickhouse: no rows in result set"
}
