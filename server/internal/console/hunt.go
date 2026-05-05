package console

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/hunt"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

const huntDetailDefaultLimit = 200

// huntList renders /hunt — paginated history + dispatch form.
func (s *Server) huntList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListHunts(r.Context(), 100)
	if err != nil {
		http.Error(w, "list hunts failed", http.StatusInternalServerError)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	flashErr, _ := s.sm.Pop(r.Context(), "flash_error").(string)
	role := s.role(r)
	render(w, r, views.HuntList(views.HuntListData{
		Hunts:  rows,
		CanRun: role == pg.RoleAnalyst || role == pg.RoleAdmin,
		Flash:  flash,
		Error:  flashErr,
	}))
}

// huntDispatch handles POST /hunt — analyst+admin gated. On success
// flashes + redirects to the new /hunt/{id}; on validation error
// re-renders the list page with the form repopulated.
func (s *Server) huntDispatch(w http.ResponseWriter, r *http.Request) {
	if s.huntHub == nil {
		http.Error(w, "hunts disabled (no hunt hub configured)", http.StatusServiceUnavailable)
		return
	}
	// Cap form size — operator-typed queries should fit comfortably
	// in 64 KiB; bigger means abuse. http.MaxBytesReader bounds the
	// total parsed body to keep ParseForm bounded (gosec G120).
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	in := hunt.DispatchInput{
		OperatorID:     s.userID(r),
		Backend:        "osquery",
		Query:          strings.TrimSpace(r.Form.Get("query")),
		HostFilter:     strings.TrimSpace(r.Form.Get("host_filter")),
		TimeoutSecs:    parseIntOrDefault(r.Form.Get("timeout_secs"), 60),
		MaxRowsPerHost: parseIntOrDefault(r.Form.Get("max_rows_per_host"), 10000),
	}
	if in.Query == "" {
		s.sm.Put(r.Context(), "flash_error", "Query is required.")
		http.Redirect(w, r, "/hunt", http.StatusFound)
		return
	}
	row, err := s.huntHub.Dispatch(r.Context(), in)
	if err != nil && !errors.Is(err, hunt.ErrNoMatchingHosts) {
		s.sm.Put(r.Context(), "flash_error", "Dispatch failed: "+err.Error())
		http.Redirect(w, r, "/hunt", http.StatusFound)
		return
	}
	msg := fmt.Sprintf("Hunt %s dispatched to %d host(s).", row.ID, row.TargetHostCount)
	if errors.Is(err, hunt.ErrNoMatchingHosts) {
		msg = fmt.Sprintf("Hunt %s recorded but matched zero hosts.", row.ID)
	}
	s.sm.Put(r.Context(), "flash", msg)
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorID:    s.userID(r),
		ActorType:  pg.ActorUser,
		Action:     "hunt.dispatched",
		TargetKind: "hunt",
		TargetID:   row.ID,
		Detail: map[string]any{
			"query":             in.Query,
			"host_filter":       in.HostFilter,
			"timeout_secs":      in.TimeoutSecs,
			"max_rows_per_host": in.MaxRowsPerHost,
			"target_host_count": row.TargetHostCount,
		},
	})
	http.Redirect(w, r, "/hunt/"+row.ID, http.StatusFound)
}

// huntDetail renders /hunt/{id} — paginated rows + per-host counts.
func (s *Server) huntDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := s.store.GetHunt(r.Context(), id)
	if err != nil {
		if errors.Is(err, pg.ErrHuntNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), huntDetailDefaultLimit)
	if limit <= 0 || limit > 1000 {
		limit = huntDetailDefaultLimit
	}
	offset := parseIntOrDefault(r.URL.Query().Get("offset"), 0)

	var (
		rows         []ch.HuntResultRow
		perHost      map[string]uint64
		hostnamesMap map[string]string
	)
	if s.chStore != nil {
		// Fetch limit+1 rows so we can detect "has next page" without a
		// separate count query.
		raw, err := s.chStore.ListHuntResults(r.Context(), id, limit+1, offset)
		if err != nil {
			http.Error(w, "list rows failed", http.StatusInternalServerError)
			return
		}
		hasNext := len(raw) > limit
		if hasNext {
			raw = raw[:limit]
		}
		rows = raw
		perHost, _ = s.chStore.CountHuntResultsPerHost(r.Context(), id)
		hostnamesMap = s.lookupHostnames(r.Context(), perHost)
		render(w, r, views.HuntDetail(views.HuntDetailData{
			Hunt:          row,
			Rows:          chRowsToView(rows),
			PerHostCount:  perHost,
			HostnamesByID: hostnamesMap,
			Limit:         limit,
			Offset:        offset,
			HasNextPage:   hasNext,
		}))
		return
	}
	render(w, r, views.HuntDetail(views.HuntDetailData{Hunt: row}))
}

// huntCSV serves /hunt/{id}.csv — full CSV export. Streams server-side;
// caps at 100k rows to bound memory.
func (s *Server) huntCSV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.GetHunt(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if s.chStore == nil {
		http.Error(w, "ch store unavailable", http.StatusServiceUnavailable)
		return
	}
	rows, err := s.chStore.ListHuntResults(r.Context(), id, 100000, 0)
	if err != nil {
		http.Error(w, "list rows failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=hunt-"+id+".csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	// Variable-shape result sets across hosts mean we cannot promise a
	// single header — emit a row-shaped CSV with host, observed_at, key,
	// value triplets so analysts get one stable schema regardless of
	// the underlying query.
	if err := cw.Write([]string{"host_id", "observed_at", "key", "value"}); err != nil {
		return
	}
	for _, row := range rows {
		stamp := row.ObservedAt.UTC().Format("2006-01-02T15:04:05Z")
		for i, col := range row.Columns {
			val := ""
			if i < len(row.Values) {
				val = row.Values[i]
			}
			if err := cw.Write([]string{row.HostID, stamp, col, val}); err != nil {
				return
			}
		}
	}
}

// chRowsToView converts ch row projections into the view-layer shape.
func chRowsToView(in []ch.HuntResultRow) []views.HuntDetailRow {
	out := make([]views.HuntDetailRow, len(in))
	for i, r := range in {
		out[i] = views.HuntDetailRow{
			HostID:     r.HostID,
			ObservedAt: r.ObservedAt,
			Columns:    r.Columns,
			Values:     r.Values,
		}
	}
	return out
}

// lookupHostnames best-effort resolves host_id → hostname for the
// per-host summary panel. A missing host (revoked since dispatch)
// falls back to bare uuid in the view; nil-safe on store errors.
func (s *Server) lookupHostnames(ctx context.Context, perHost map[string]uint64) map[string]string {
	out := make(map[string]string, len(perHost))
	for id := range perHost {
		host, err := s.store.GetHost(ctx, id)
		if err != nil {
			continue
		}
		out[id] = host.Hostname
	}
	return out
}

func parseIntOrDefault(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}
