package pg

import "testing"

func TestIsValidAlertTransition(t *testing.T) {
	cases := []struct {
		from, to AlertStatus
		want     bool
	}{
		// Allowed paths from PROJECT.md §5.
		{AlertNew, AlertAcknowledged, true},
		{AlertNew, AlertInProgress, true},
		{AlertNew, AlertClosed, true},
		{AlertAcknowledged, AlertInProgress, true},
		{AlertAcknowledged, AlertClosed, true},
		{AlertInProgress, AlertClosed, true},

		// Self-transitions are no-ops, never allowed.
		{AlertNew, AlertNew, false},
		{AlertAcknowledged, AlertAcknowledged, false},
		{AlertClosed, AlertClosed, false},

		// Backward / sideways moves are rejected. Phase 6 #116 lit up
		// the closed → in_progress reopen path; everything else stays
		// rejected.
		{AlertAcknowledged, AlertNew, false},
		{AlertInProgress, AlertAcknowledged, false},
		{AlertInProgress, AlertNew, false},
		{AlertClosed, AlertNew, false},
		{AlertClosed, AlertAcknowledged, false},
		{AlertClosed, AlertInProgress, true}, // Phase 6 #116 reopen-alert

		// Garbage statuses fail closed.
		{AlertStatus("nonsense"), AlertClosed, false},
		{AlertNew, AlertStatus("garbage"), false},
	}
	for _, c := range cases {
		if got := IsValidAlertTransition(c.from, c.to); got != c.want {
			t.Errorf("IsValidAlertTransition(%q, %q) = %v, want %v",
				c.from, c.to, got, c.want)
		}
	}
}
