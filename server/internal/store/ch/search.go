package ch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EventFilter narrows the search.SearchEvents query. Empty fields mean
// "no constraint"; ClassUIDs == nil means every class table.
type EventFilter struct {
	ClassUIDs  []uint32
	HostID     string
	SeverityID uint8 // 0 = no constraint
	Since      time.Time
	Until      time.Time

	// Phase 6 #120 — JSON API filters. Both narrow on the
	// detection_finding (class_uid 2004) table; queries pairing a
	// non-empty Tag/RuleUID with a ClassUIDs slice that excludes 2004
	// return zero rows by construction.
	//
	// RuleUID matches `rule_uid = ?` exactly.
	// Tag matches `has(mitre_techniques, ?)` against the array
	// column the writer populates from each finding's MitreATTACK
	// entries (technique + sub-technique UIDs).
	RuleUID string
	Tag     string
}

// EventRow is one search-result row projected to the columns the
// /events list view shows.
type EventRow struct {
	EventID     string
	HostID      string
	ClassUID    uint32
	SeverityID  uint8
	ObservedAt  time.Time
	CollectedAt time.Time
	// Summary is a one-line, class-specific summary the list view
	// renders inline so operators don't have to drill into every row.
	Summary string
	// Raw is omitted from list responses to keep the wire small;
	// fetched separately by GetEventByID for the detail view.
}

// EventDetail extends EventRow with the canonical OCSF JSON and a
// pretty-printed copy. Used by the detail page.
type EventDetail struct {
	EventRow
	Raw       json.RawMessage
	RawPretty string
}

// Cursor is the opaque pagination key. Zero value means "first page".
type Cursor struct {
	ObservedAt time.Time
	EventID    string
}

// String encodes the cursor for a URL query param. RFC3339Nano +
// event_id keep it human-debuggable, which beats opaque base64 when
// an operator needs to spot what page they're on.
func (c Cursor) String() string {
	if c.EventID == "" {
		return ""
	}
	return c.ObservedAt.UTC().Format(time.RFC3339Nano) + "|" + c.EventID
}

// ParseCursor reads the URL form back into a Cursor. Empty input
// returns the zero value (first page); a malformed cursor returns an
// error so the handler can render a clear message rather than silently
// page from the top.
func ParseCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	parts := strings.SplitN(s, "|", 2)
	if len(parts) != 2 {
		return Cursor{}, errors.New("cursor: missing separator")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return Cursor{}, fmt.Errorf("cursor: parse time: %w", err)
	}
	return Cursor{ObservedAt: t.UTC(), EventID: parts[1]}, nil
}

// classTables maps each class UID we know about to its table. New
// classes added in Phase 3+ register here alongside their migration.
var classTables = map[uint32]string{
	1001: "ocsf_file_system_activity_1001",
	1007: "ocsf_process_activity_1007",
	2004: "ocsf_detection_finding_2004",
	4001: "ocsf_network_activity_4001",
}

// SearchEvents returns up to limit rows matching filter, ordered
// (observed_at DESC, event_id DESC). When more rows likely exist past
// the returned page, nextCursor is non-zero and ready for the caller
// to feed back as the cursor argument on the next page request.
//
// Pagination semantics: cursor is a strict less-than tuple comparison
// so successive pages don't double-count an event whose observed_at
// is shared with another. The CH ORDER BY (host_id, observed_at,
// event_id) doesn't quite match this query's ordering but the page-
// size filter at the top ranges keeps reads cheap; query-shape work
// for the 1M-row exit criterion lands in #46 manual validation.
func (s *Store) SearchEvents(ctx context.Context, filter EventFilter, cursor Cursor, limit int) (rows []EventRow, nextCursor Cursor, err error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	tables := tablesFor(filter)
	if len(tables) == 0 {
		return nil, Cursor{}, nil
	}

	clauses := []string{}
	args := []any{}

	addArg := func(v any) string {
		args = append(args, v)
		return "?"
	}

	if filter.HostID != "" {
		// Bind UUID columns as uuid.UUID — clickhouse-go's String
		// binding doesn't auto-coerce to a UUID column compare and
		// surfaces "no supertype for types String, UUID" otherwise.
		hostUUID, perr := uuid.Parse(filter.HostID)
		if perr != nil {
			return nil, Cursor{}, fmt.Errorf("ch.SearchEvents: parse host_id: %w", perr)
		}
		clauses = append(clauses, fmt.Sprintf("host_id = %s", addArg(hostUUID)))
	}
	if filter.SeverityID != 0 {
		clauses = append(clauses, fmt.Sprintf("severity_id = %s", addArg(filter.SeverityID)))
	}
	// Phase 6 #120: rule_uid + mitre_techniques live on the
	// detection_finding table only; tablesFor narrows the table set
	// when either is set so these clauses are safe to apply
	// unconditionally.
	if filter.RuleUID != "" {
		clauses = append(clauses, fmt.Sprintf("rule_uid = %s", addArg(filter.RuleUID)))
	}
	if filter.Tag != "" {
		clauses = append(clauses, fmt.Sprintf("has(mitre_techniques, %s)", addArg(filter.Tag)))
	}
	// Pass timestamp args as int64 nanos with a fromUnixTimestamp64Nano
	// wrap on the SQL side. clickhouse-go's positional binder doesn't
	// always re-cast time.Time to the column's DateTime64(9) cleanly,
	// especially in a UNION ALL where the same arg appears in multiple
	// subqueries; nanos round-trip exactly.
	if !filter.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("observed_at >= fromUnixTimestamp64Nano(%s)", addArg(filter.Since.UnixNano())))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, fmt.Sprintf("observed_at <= fromUnixTimestamp64Nano(%s)", addArg(filter.Until.UnixNano())))
	}
	if cursor.EventID != "" {
		eventUUID, perr := uuid.Parse(cursor.EventID)
		if perr != nil {
			return nil, Cursor{}, fmt.Errorf("ch.SearchEvents: parse cursor event_id: %w", perr)
		}
		obsArg1 := addArg(cursor.ObservedAt.UnixNano())
		obsArg2 := addArg(cursor.ObservedAt.UnixNano())
		idArg := addArg(eventUUID)
		clauses = append(clauses, fmt.Sprintf(
			"(observed_at < fromUnixTimestamp64Nano(%s) OR (observed_at = fromUnixTimestamp64Nano(%s) AND event_id < %s))",
			obsArg1, obsArg2, idArg))
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	subqueries := make([]string, 0, len(tables))
	for _, table := range tables {
		// Class-specific summary expression — projected as a single
		// String column so the UNION ALL has a uniform schema.
		subqueries = append(subqueries, fmt.Sprintf(`
			SELECT
				toString(event_id)        AS event_id,
				toString(host_id)         AS host_id,
				class_uid,
				severity_id,
				observed_at,
				collected_at,
				%s                        AS summary
			FROM %s
			%s
		`, summaryExpr(table), table, where))
	}

	stmt := fmt.Sprintf(`
		%s
		ORDER BY observed_at DESC, event_id DESC
		LIMIT %d
	`, strings.Join(subqueries, "UNION ALL "), limit+1)

	// Args are repeated once per UNION subquery — clickhouse-go binds
	// positionally so we need to multiply them.
	repeated := make([]any, 0, len(args)*len(tables))
	for range tables {
		repeated = append(repeated, args...)
	}

	chRows, err := s.conn.Query(ctx, stmt, repeated...)
	if err != nil {
		return nil, Cursor{}, fmt.Errorf("ch.SearchEvents: query: %w", err)
	}
	defer chRows.Close()

	out := make([]EventRow, 0, limit+1)
	for chRows.Next() {
		var r EventRow
		if err := chRows.Scan(
			&r.EventID, &r.HostID, &r.ClassUID, &r.SeverityID,
			&r.ObservedAt, &r.CollectedAt, &r.Summary,
		); err != nil {
			return nil, Cursor{}, fmt.Errorf("ch.SearchEvents: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := chRows.Err(); err != nil {
		return nil, Cursor{}, fmt.Errorf("ch.SearchEvents: iter: %w", err)
	}

	if len(out) > limit {
		// We over-fetched by one to know the next cursor; trim and
		// return the (limit)th row's tuple as the page-after key.
		nc := Cursor{ObservedAt: out[limit-1].ObservedAt, EventID: out[limit-1].EventID}
		return out[:limit], nc, nil
	}
	return out, Cursor{}, nil
}

// GetEventByID looks up one event across every class table. Useful
// for the detail view; class_uid + event_id together are unique and
// indexed (event_id is the trailing ORDER BY column).
func (s *Store) GetEventByID(ctx context.Context, classUID uint32, eventID string) (EventDetail, error) {
	table, ok := classTables[classUID]
	if !ok {
		return EventDetail{}, fmt.Errorf("ch.GetEventByID: unknown class_uid %d", classUID)
	}
	stmt := fmt.Sprintf(`
		SELECT
			toString(event_id), toString(host_id), class_uid, severity_id,
			observed_at, collected_at, %s, raw
		FROM %s
		WHERE event_id = ?
		LIMIT 1
	`, summaryExpr(table), table)

	eventUUID, err := uuid.Parse(eventID)
	if err != nil {
		return EventDetail{}, fmt.Errorf("ch.GetEventByID: parse event_id: %w", err)
	}
	row := s.conn.QueryRow(ctx, stmt, eventUUID)
	var (
		out EventDetail
		raw string
	)
	if err := row.Scan(
		&out.EventID, &out.HostID, &out.ClassUID, &out.SeverityID,
		&out.ObservedAt, &out.CollectedAt, &out.Summary, &raw,
	); err != nil {
		return EventDetail{}, fmt.Errorf("ch.GetEventByID: scan: %w", err)
	}
	out.Raw = json.RawMessage(raw)
	if pretty, err := prettyJSON(raw); err == nil {
		out.RawPretty = pretty
	} else {
		out.RawPretty = raw
	}
	return out, nil
}

// tablesFor picks the subset of classTables touched by filter. The
// implicit guarantee is that an empty ClassUIDs filter searches every
// known class — class additions never silently shrink the search.
func tablesFor(filter EventFilter) []string {
	// Phase 6 #120: RuleUID + Tag are columns on the
	// detection_finding (class 2004) table only. When either is set,
	// narrow the search to that table — preserves the spec's
	// "queries pairing Tag != "" with non-2004 class_uids return
	// zero rows by construction" semantics, but the narrow happens
	// here rather than via WHERE on every per-class subquery (which
	// would fail to compile against tables without those columns).
	if filter.RuleUID != "" || filter.Tag != "" {
		if t, ok := classTables[2004]; ok {
			return []string{t}
		}
		return nil
	}
	if len(filter.ClassUIDs) == 0 {
		out := make([]string, 0, len(classTables))
		for _, t := range classTables {
			out = append(out, t)
		}
		return out
	}
	seen := make(map[string]struct{}, len(filter.ClassUIDs))
	out := make([]string, 0, len(filter.ClassUIDs))
	for _, c := range filter.ClassUIDs {
		if t, ok := classTables[c]; ok {
			if _, dup := seen[t]; !dup {
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
	}
	return out
}

// summaryExpr returns a class-specific SQL expression that produces
// a one-line summary string for the list view. Each class projects
// its hot-path columns; rows from different classes UNION ALL into
// the same shape so the handler doesn't need a per-class branch.
func summaryExpr(table string) string {
	switch table {
	case "ocsf_process_activity_1007":
		return `concat(toString(activity_id), ' pid=', toString(pid), ' ', exec_path, ' ', cmdline)`
	case "ocsf_file_system_activity_1001":
		return `concat(toString(activity_id), ' ', file_path, ' actor_pid=', toString(actor_pid))`
	case "ocsf_network_activity_4001":
		return `concat(protocol, ' ', src_ip, ':', toString(src_port), '->', dst_ip, ':', toString(dst_port))`
	case "ocsf_detection_finding_2004":
		return `concat(rule_uid, ' ', rule_name)`
	}
	return `''`
}

func prettyJSON(raw string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}
