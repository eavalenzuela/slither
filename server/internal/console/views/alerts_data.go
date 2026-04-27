package views

import (
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// AlertsListData drives the /alerts list page.
type AlertsListData struct {
	Alerts        []pg.AlertRow
	Now           time.Time
	StatusFilter  pg.AlertStatus // "" = all
	HostIDFilter  string
	NextCursorURL string
	Flash         string
	IsAnalyst     bool
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
