package console

import (
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestAllowedNextStatuses(t *testing.T) {
	cases := []struct {
		from pg.AlertStatus
		want []pg.AlertStatus
	}{
		{pg.AlertNew, []pg.AlertStatus{pg.AlertAcknowledged, pg.AlertInProgress, pg.AlertClosed}},
		{pg.AlertAcknowledged, []pg.AlertStatus{pg.AlertInProgress, pg.AlertClosed}},
		{pg.AlertInProgress, []pg.AlertStatus{pg.AlertClosed}},
		{pg.AlertClosed, []pg.AlertStatus{}},
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
