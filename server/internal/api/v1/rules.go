// Phase 6 #120 — GET /api/v1/rules.
//
// Slim projection of pg.ListEnabledRules. Optional `?since=` filter
// returns rules whose updated_at is >= the cutoff; `?technique=`
// filters to rules whose source YAML carries the given attack tag
// (substring match against the lowercased source). Both filters are
// applied in-process — the rule corpus is small (single-digit-MB at
// fleet scale), so a streaming filter beats a Phase 6 schema
// migration to add tag arrays per rule.

package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

type ruleSummary struct {
	UID            string    `json:"uid"`
	Name           string    `json:"name"`
	Classification string    `json:"classification,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type rulesListResponse struct {
	Rules []ruleSummary `json:"rules"`
}

func (s *Server) rulesList(w http.ResponseWriter, r *http.Request) {
	if s.pg == nil {
		writeError(w, http.StatusServiceUnavailable,
			"pg_unavailable", "Postgres store not wired")
		return
	}
	q := r.URL.Query()
	var since time.Time
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_since", err.Error())
			return
		}
		since = t.UTC()
	}
	technique := strings.ToLower(strings.TrimSpace(q.Get("technique")))

	rows, err := s.pg.ListEnabledRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"internal_error", "rules list failed")
		return
	}

	out := make([]ruleSummary, 0, len(rows))
	for _, row := range rows {
		if !since.IsZero() && row.UpdatedAt.Before(since) {
			continue
		}
		if technique != "" {
			// Substring match against the lowercased source — the
			// canonical Sigma tag form is `attack.t1070.003` so a
			// query for `t1070` matches both the parent + the
			// sub-technique without re-parsing YAML.
			if !strings.Contains(strings.ToLower(row.SourceYAML), technique) {
				continue
			}
		}
		out = append(out, ruleSummary{
			UID:            row.UID,
			Name:           row.Name,
			Classification: row.Classification,
			UpdatedAt:      row.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, rulesListResponse{Rules: out})
}

// truncString returns s clipped to at most n bytes. Reserved for a
// future Phase 7 endpoint that surfaces rule descriptions; pulled in
// here so the v1 package stays self-contained.
func truncString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// _ keeps truncString in the binary even when no current handler
// references it — avoids unused-function lint complaints while we
// stage the Phase 7 hook.
var _ = truncString

// avoid unused-import warning until rule helpers expand.
var _ = pg.Rule{}
