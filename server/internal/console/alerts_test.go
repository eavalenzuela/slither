package console

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestParseDatetimeLocal(t *testing.T) {
	cases := []struct {
		in        string
		wantBlank bool
		wantHour  int
		wantErr   bool
	}{
		{"", true, 0, false},
		{"   ", true, 0, false},
		{"2026-04-27T15:30", false, 15, false},
		{"not-a-date", false, 0, true},
	}
	for _, c := range cases {
		got, raw, err := parseDatetimeLocal(c.in)
		switch {
		case c.wantErr:
			if err == nil {
				t.Errorf("parseDatetimeLocal(%q) want error, got nil", c.in)
			}
			continue
		case err != nil:
			t.Errorf("parseDatetimeLocal(%q) unexpected err: %v", c.in, err)
			continue
		}
		if c.wantBlank {
			if !got.IsZero() || raw != "" {
				t.Errorf("parseDatetimeLocal(%q) blank path: got=%v raw=%q", c.in, got, raw)
			}
			continue
		}
		if got.Hour() != c.wantHour || got.Location() != time.UTC {
			t.Errorf("parseDatetimeLocal(%q) = %v, want hour=%d UTC", c.in, got, c.wantHour)
		}
		if raw != strings.TrimSpace(c.in) {
			t.Errorf("parseDatetimeLocal(%q) raw=%q, want echo of input", c.in, raw)
		}
	}
}

func TestAlertsURLWithCursor_PreservesEveryFilter(t *testing.T) {
	filters := views.AlertsListFilters{
		Status:     pg.AlertNew,
		HostID:     "11111111-1111-4111-8111-111111111111",
		RuleUID:    "rule-x",
		SeverityID: 4,
		AssignedTo: "unassigned",
		Since:      "2026-04-27T00:00",
		Until:      "2026-04-27T23:59",
	}
	cursor := pg.AlertCursor{
		CreatedAt: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC),
		AlertID:   "22222222-2222-4222-8222-222222222222",
	}
	got := views.AlertsURLWithCursor(filters, cursor)
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if parsed.Path != "/alerts" {
		t.Errorf("path = %q", parsed.Path)
	}
	q := parsed.Query()
	want := map[string]string{
		"status":      "new",
		"host_id":     "11111111-1111-4111-8111-111111111111",
		"rule_uid":    "rule-x",
		"severity":    "4",
		"assigned_to": "unassigned",
		"since":       "2026-04-27T00:00",
		"until":       "2026-04-27T23:59",
		"after_id":    "22222222-2222-4222-8222-222222222222",
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("query[%q] = %q, want %q", k, got, v)
		}
	}
	if q.Get("after_at") == "" {
		t.Errorf("after_at param missing")
	}
}

func TestAlertsURLWithCursor_BlankFiltersBlankURL(t *testing.T) {
	got := views.AlertsURLWithCursor(views.AlertsListFilters{}, pg.AlertCursor{})
	if got != "/alerts" {
		t.Errorf("blank url = %q, want /alerts", got)
	}
}

func TestAllowedNextStatuses(t *testing.T) {
	cases := []struct {
		from pg.AlertStatus
		want []pg.AlertStatus
	}{
		{pg.AlertNew, []pg.AlertStatus{pg.AlertAcknowledged, pg.AlertInProgress, pg.AlertClosed}},
		{pg.AlertAcknowledged, []pg.AlertStatus{pg.AlertInProgress, pg.AlertClosed}},
		{pg.AlertInProgress, []pg.AlertStatus{pg.AlertClosed}},
		// Phase 6 #116 lit up the reopen path.
		{pg.AlertClosed, []pg.AlertStatus{pg.AlertInProgress}},
		{pg.AlertStatus(""), []pg.AlertStatus{}},
	}
	for _, c := range cases {
		got := allowedNextStatuses(c.from)
		if len(got) != len(c.want) {
			t.Errorf("allowedNextStatuses(%q) len = %d, want %d (got=%v)",
				c.from, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("allowedNextStatuses(%q)[%d] = %q, want %q",
					c.from, i, got[i], c.want[i])
			}
		}
	}
}
