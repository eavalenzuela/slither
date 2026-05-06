package views

import (
	"fmt"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// EventsPageData drives the events list page. NextCursor is the
// already-formatted query value to append to the next-page link;
// empty means "this is the last page".
type EventsPageData struct {
	Rows       []ch.EventRow
	Filter     EventsFilter
	NextCursor string
	// RawQuery is r.URL.RawQuery passed through so the Phase 6 #115
	// "Save filter" partial can capture exactly what the operator
	// has applied. Empty string is fine — saves a no-filter view.
	RawQuery string

	// Phase 6 #116(a) — text query language. QueryText is the raw
	// `q=` value the operator submitted; ParseError is non-empty
	// when the parser rejected it (handler clears Filter so the
	// page renders empty results). UnknownTokens names axes the
	// parser couldn't classify so the page surfaces them as a hint
	// rather than silently dropping.
	QueryText     string
	ParseError    string
	UnknownTokens []string

	// Phase 6 #121 follow-up #6 — when the operator's host: filter is
	// a hostname that didn't resolve to any enrolled host,
	// UnknownHost echoes the original input so the page can surface
	// "no host named foo" rather than "search failed". Rows is left
	// empty in this case (no CH query is issued).
	UnknownHost string
}

// EventsHistoryData drives /events/history — the user's last-50
// query strings on the events surface, newest-first.
type EventsHistoryData struct {
	Rows []pg.QueryHistoryRow
}

// EventsFilter mirrors the query params accepted by the page so the
// template can re-render the form with the current values.
type EventsFilter struct {
	HostID     string
	ClassUID   string // string-form so the form round-trips empties
	SeverityID string
	Since      string // RFC3339, optional
	Until      string
}

// EventDetailData drives the per-event detail page.
type EventDetailData struct {
	Event ch.EventDetail
}

// formatTime is exposed to templ via a templ.Component-friendly helper.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// classLabel maps class_uid to an operator-friendly label.
func classLabel(uid uint32) string {
	switch uid {
	case 1001:
		return "file"
	case 1007:
		return "process"
	case 2004:
		return "detection"
	case 4001:
		return "network"
	}
	return fmt.Sprintf("class %d", uid)
}

// severityLabel maps the OCSF severity_id to its short string.
func severityLabel(s uint8) string {
	switch s {
	case 1:
		return "info"
	case 2:
		return "low"
	case 3:
		return "medium"
	case 4:
		return "high"
	case 5:
		return "critical"
	case 6:
		return "fatal"
	}
	return "—"
}

// detailHref builds the per-event detail URL — class_uid is required
// in addition to event_id because event_id is only unique within its
// class table (UUIDv7 collisions are vanishingly unlikely but the CH
// schema doesn't enforce cross-table uniqueness, and the lookup is
// faster with the class hint).
func detailHref(classUID uint32, eventID string) string {
	return fmt.Sprintf("/events/%d/%s", classUID, eventID)
}
