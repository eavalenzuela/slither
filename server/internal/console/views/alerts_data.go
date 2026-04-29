package views

import (
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// AlertsListData drives the /alerts list page. Filter values are
// rendered back into the form so an operator can refine without
// retyping. The handler is responsible for validating each filter
// against pg.AlertFilter shape; the view trusts what it gets.
type AlertsListData struct {
	Alerts         []pg.AlertRow
	Now            time.Time
	StatusFilter   pg.AlertStatus // "" = all
	HostIDFilter   string
	RuleUIDFilter  string
	SeverityFilter uint8 // 0 = all
	AssigneeFilter string
	SinceFilter    string // RFC3339-truncated, blank = none
	UntilFilter    string
	NextCursorURL  string
	Flash          string
	IsAnalyst      bool
}

// AlertDetailData drives the /alerts/{id} detail page. Allowed
// transitions are pre-computed server-side so the buttons render
// matching pg.IsValidAlertTransition without re-implementing the
// rule in templ.
type AlertDetailData struct {
	Alert       pg.AlertRow
	AllowedNext []pg.AlertStatus
	IsAnalyst   bool
	Flash       string
	// ShowGraph signals whether to embed the alert flow-graph image
	// (#64). False when the server was started without a graph cache
	// or when the alert has no event_ids.
	ShowGraph bool
}

// AlertsCursorLayout is the time format the /alerts pagination
// cursor encodes in. Exported so the handler's parser stays in sync
// with views.AlertsURLWithCursor.
func AlertsCursorLayout() string { return timeRFC3339Nano }

// AlertSeverityLabel maps the OCSF severity_id integer to the
// human-readable label /alerts shows next to the severity number.
// Defined in views so templ doesn't have to handle the integer
// switch inline.
func AlertSeverityLabel(s uint8) string {
	switch s {
	case 1:
		return "Informational"
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	case 6:
		return "Other"
	}
	return ""
}
