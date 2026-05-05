package console

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/ch"
)

// eventsPageSize bounds how many rows the list view fetches per page.
// Operators paginate via the cursor link rather than scrolling huge
// pages so the SELECT remains cheap on large CH partitions.
const eventsPageSize = 50

// eventsList renders /events. Filters come from query params; the
// cursor is opaque (handled inside ch.SearchEvents) and round-trips
// via the "cursor" param on the next-page link.
func (s *Server) eventsList(w http.ResponseWriter, r *http.Request) {
	if s.chStore == nil {
		http.Error(w, "events store unavailable", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	filter, viewFilter := parseEventsFilter(q)

	cursor, err := ch.ParseCursor(q.Get("cursor"))
	if err != nil {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}

	rows, next, err := s.chStore.SearchEvents(r.Context(), filter, cursor, eventsPageSize)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}

	render(w, r, views.Events(views.EventsPageData{
		Rows:       rows,
		Filter:     viewFilter,
		NextCursor: next.String(),
		RawQuery:   r.URL.RawQuery,
	}))
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
