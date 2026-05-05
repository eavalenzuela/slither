package console

import (
	"net/url"
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestEncodeSavedQueryURL_Empty(t *testing.T) {
	t.Parallel()
	got := EncodeSavedQueryURL(pg.SavedQuery{Surface: pg.SavedQuerySurfaceEvents})
	if got != "/events" {
		t.Errorf("got %q, want /events", got)
	}
}

func TestEncodeSavedQueryURL_RoundTrips(t *testing.T) {
	t.Parallel()
	q := pg.SavedQuery{
		Surface: pg.SavedQuerySurfaceAlerts,
		Params:  map[string]string{"status": "new", "host_id": "h-1"},
	}
	got := EncodeSavedQueryURL(q)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if u.Path != "/alerts" {
		t.Errorf("path = %q, want /alerts", u.Path)
	}
	v := u.Query()
	if v.Get("status") != "new" || v.Get("host_id") != "h-1" {
		t.Errorf("params didn't round-trip: %v", v)
	}
}

func TestFlattenParams_FirstWins(t *testing.T) {
	t.Parallel()
	in := url.Values{
		"status": []string{"new", "in_progress"},
		"host":   []string{"h-1"},
	}
	got := flattenParams(in)
	if got["status"] != "new" {
		t.Errorf("status = %q, want new (first value wins)", got["status"])
	}
	if got["host"] != "h-1" {
		t.Errorf("host = %q, want h-1", got["host"])
	}
}
