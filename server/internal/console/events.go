package console

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// eventsPageSize bounds how many rows the list view fetches per page.
// Operators paginate via the cursor link rather than scrolling huge
// pages so the SELECT remains cheap on large CH partitions.
const eventsPageSize = 50

// eventsList renders /events. Filters come from query params; the
// cursor is opaque (handled inside ch.SearchEvents) and round-trips
// via the "cursor" param on the next-page link.
//
// Phase 6 #116(a): a `q=` param carrying free-form text takes
// precedence over the structured form fields. ParseEventsQuery turns
// `host:foo class:1007 since:24h` into the same EventFilter shape and
// records a query_history row so the operator can re-run it from
// /events/history. Parse errors surface as a flash + the operator's
// original query stays in the search box.
func (s *Server) eventsList(w http.ResponseWriter, r *http.Request) {
	if s.chStore == nil {
		http.Error(w, "events store unavailable", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	rawQ := strings.TrimSpace(q.Get("q"))
	var (
		filter     ch.EventFilter
		viewFilter views.EventsFilter
		parseError string
		unknowns   []string
	)
	if rawQ != "" {
		parsed, perr := ParseEventsQuery(rawQ)
		if perr != nil {
			parseError = perr.Error()
			// Render the page with no filter so the operator sees the
			// parse error + can fix the input.
		} else {
			unknowns = parsed.Unknown
			// Convert ParsedQuery into both shapes the page consumes.
			pv := parsed.ToURLValues()
			merged := q
			for k, vs := range pv {
				if len(vs) > 0 {
					merged[k] = vs
				}
			}
			filter, viewFilter = parseEventsFilter(merged)
			if uid := s.userID(r); uid != "" {
				if err := s.store.RecordQuery(r.Context(), uid,
					pg.SavedQuerySurfaceEvents, "q="+rawQ); err != nil {
					// Best-effort — a history-write blip can't fail
					// the page render.
					_ = err
				}
			}
		}
	} else {
		filter, viewFilter = parseEventsFilter(q)
	}

	cursor, err := ch.ParseCursor(q.Get("cursor"))
	if err != nil {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}

	// Phase 6 #121 follow-up #6 — operators type hostnames into
	// host:foo without knowing the row's UUID. Resolve hostnames here
	// so SearchEvents always sees a UUID; on miss render an empty
	// page with an "unknown host" notice rather than 500'ing.
	hostInput := filter.HostID
	resolved, rerr := resolveHostFilter(r.Context(), s.store, hostInput)
	switch {
	case errors.Is(rerr, pg.ErrHostNotFound):
		render(w, r, views.Events(views.EventsPageData{
			Filter:        viewFilter,
			RawQuery:      r.URL.RawQuery,
			QueryText:     rawQ,
			ParseError:    parseError,
			UnknownTokens: unknowns,
			UnknownHost:   hostInput,
		}))
		return
	case rerr != nil:
		http.Error(w, "host lookup failed", http.StatusInternalServerError)
		return
	}
	filter.HostID = resolved

	rows, next, err := s.chStore.SearchEvents(r.Context(), filter, cursor, eventsPageSize)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}

	render(w, r, views.Events(views.EventsPageData{
		Rows:          rows,
		Filter:        viewFilter,
		NextCursor:    next.String(),
		RawQuery:      r.URL.RawQuery,
		QueryText:     rawQ,
		ParseError:    parseError,
		UnknownTokens: unknowns,
	}))
}

// resolveHostFilter returns the UUID form of input. If input parses as
// a UUID it's returned unchanged. If input is a hostname, lookup goes
// through pg.GetHostByName; ErrHostNotFound surfaces unchanged so the
// caller can render an "unknown host" notice. Phase 6 #121 follow-up
// #6 — extracted for unit testability.
func resolveHostFilter(ctx context.Context, store hostByNameLookup, input string) (string, error) {
	if input == "" {
		return "", nil
	}
	if _, err := uuid.Parse(input); err == nil {
		return input, nil
	}
	row, err := store.GetHostByName(ctx, input)
	if err != nil {
		return "", err
	}
	return row.ID, nil
}

// hostByNameLookup is the pg.Store subset resolveHostFilter needs;
// keeping it narrow lets the unit test stub without dragging the full
// store interface in.
type hostByNameLookup interface {
	GetHostByName(ctx context.Context, hostname string) (pg.HostRow, error)
}

// eventsHistory renders /events/history — the user's last-50 query
// strings (most recent first). Click-to-rerun links straight back to
// /events?q=<...>.
func (s *Server) eventsHistory(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(r)
	if uid == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rows, err := s.store.ListQueryHistory(r.Context(), uid, pg.SavedQuerySurfaceEvents, 50)
	if err != nil {
		http.Error(w, "list history failed", http.StatusInternalServerError)
		return
	}
	render(w, r, views.EventsHistory(views.EventsHistoryData{Rows: rows}))
}

// eventDetail renders /events/{class_uid}/{event_id}.
func (s *Server) eventDetail(w http.ResponseWriter, r *http.Request) {
	if s.chStore == nil {
		http.Error(w, "events store unavailable", http.StatusServiceUnavailable)
		return
	}

	classStr := chi.URLParam(r, "class_uid")
	eventID := chi.URLParam(r, "event_id")
	classUID, err := strconv.ParseUint(classStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid class_uid", http.StatusBadRequest)
		return
	}

	detail, err := s.chStore.GetEventByID(r.Context(), uint32(classUID), eventID) //nolint:gosec // bounded by ParseUint(0,32)
	if err != nil {
		http.Error(w, "event not found", http.StatusNotFound)
		return
	}

	render(w, r, views.EventDetail(views.EventDetailData{Event: detail}))
}

// parseEventsFilter converts the URL query into both the CH filter
// (typed) and the form-rebuild data (string). Returning both keeps
// the form sticky on submit without retyping every param twice.
func parseEventsFilter(q map[string][]string) (ch.EventFilter, views.EventsFilter) {
	get := func(k string) string {
		if vs, ok := q[k]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	vf := views.EventsFilter{
		HostID:     get("host_id"),
		ClassUID:   get("class_uid"),
		SeverityID: get("severity_id"),
		Since:      get("since"),
		Until:      get("until"),
	}

	cf := ch.EventFilter{HostID: vf.HostID}
	if vf.ClassUID != "" {
		if n, err := strconv.ParseUint(vf.ClassUID, 10, 32); err == nil {
			cf.ClassUIDs = []uint32{uint32(n)} //nolint:gosec // bounded by ParseUint(0,32)
		}
	}
	if vf.SeverityID != "" {
		if n, err := strconv.ParseUint(vf.SeverityID, 10, 8); err == nil {
			cf.SeverityID = uint8(n) //nolint:gosec // bounded by ParseUint(0,8)
		}
	}
	if vf.Since != "" {
		if t, err := time.Parse(time.RFC3339Nano, vf.Since); err == nil {
			cf.Since = t.UTC()
		}
	}
	if vf.Until != "" {
		if t, err := time.Parse(time.RFC3339Nano, vf.Until); err == nil {
			cf.Until = t.UTC()
		}
	}
	return cf, vf
}
