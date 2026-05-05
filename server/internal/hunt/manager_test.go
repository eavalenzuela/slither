package hunt

import (
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestMatchHostFilter(t *testing.T) {
	host := pg.HuntHostRef{ID: "11111111-2222-3333-4444-555555555555", Hostname: "web-01"}
	cases := []struct {
		filter string
		want   bool
	}{
		{"", true},
		{"web", true},
		{"WEB", true},
		{"22", true},   // matches uuid prefix
		{"db-", false}, // no match
		{"55-66", false},
	}
	for _, c := range cases {
		got := MatchHostFilter(c.filter, host)
		if got != c.want {
			t.Errorf("filter %q on %+v: got %t, want %t", c.filter, host, got, c.want)
		}
	}
}
