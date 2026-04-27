package console

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

const alertsPageSize = 50

// alertsList renders /alerts. Filters: status, host_id. Cursor
// pagination via after_at + after_id query params (same shape as the
// /events page from #43).
func (s *Server) alertsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	statusFilter := pg.AlertStatus(strings.TrimSpace(q.Get("status")))
	hostIDFilter := strings.TrimSpace(q.Get("host_id"))

	filter := pg.AlertFilter{HostID: hostIDFilter}
	if statusFilter != "" {
		filter.Statuses = []pg.AlertStatus{statusFilter}
	}

	cursor := pg.AlertCursor{}
	if id := q.Get("after_id"); id != "" {
		if t, err := time.Parse(views.AlertsCursorLayout(), q.Get("after_at")); err == nil {
			cursor.CreatedAt = t
			cursor.AlertID = id
		}
	}

	alerts, next, err := s.store.ListAlerts(r.Context(), filter, cursor, alertsPageSize)
	if err != nil {
		http.Error(w, "list alerts failed", http.StatusInternalServerError)
		return
	}

	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	role := s.role(r)
	render(w, r, views.AlertsList(views.AlertsListData{
		Alerts:        alerts,
		Now:           time.Now().UTC(),
		StatusFilter:  statusFilter,
		HostIDFilter:  hostIDFilter,
		NextCursorURL: nextCursorURL(statusFilter, hostIDFilter, next),
		Flash:         flash,
		IsAnalyst:     role == pg.RoleAnalyst || role == pg.RoleAdmin,
	}))
}

// alertDetail renders /alerts/{id}. 404s on missing rows; 400 on a
// non-UUID id so a typo doesn't reach the DB.
func (s *Server) alertDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row, err := s.store.GetAlert(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load alert failed", http.StatusInternalServerError)
		return
	}

	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	role := s.role(r)
	render(w, r, views.AlertDetail(views.AlertDetailData{
		Alert:       row,
		AllowedNext: allowedNextStatuses(row.Status),
		IsAnalyst:   role == pg.RoleAnalyst || role == pg.RoleAdmin,
		Flash:       flash,
	}))
}

// alertTransition handles POST /alerts/{id}/transition. The route is
// wrapped in RequireRole(analyst,admin) at registration; this handler
// trusts the role check and focuses on parsing + delegating.
func (s *Server) alertTransition(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	to := pg.AlertStatus(strings.TrimSpace(r.PostFormValue("to")))
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if to == "" {
		http.Error(w, "missing target status", http.StatusBadRequest)
		return
	}

	row, err := s.store.TransitionAlert(r.Context(), pg.AlertTransition{
		AlertID: id,
		To:      to,
		Reason:  reason,
		Actor:   s.userID(r),
	})
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, pg.ErrInvalidTransition):
		s.sm.Put(r.Context(), "flash", "Transition not allowed from current state.")
		http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
		return
	case err != nil:
		http.Error(w, "transition failed", http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), "flash", "Alert transitioned to "+string(row.Status)+".")
	http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
}

// allowedNextStatuses computes the buttons the detail page should
// render given the alert's current status. Order is intent-stable so
// the UI shows ack before close even when both are available.
func allowedNextStatuses(from pg.AlertStatus) []pg.AlertStatus {
	candidates := []pg.AlertStatus{pg.AlertAcknowledged, pg.AlertInProgress, pg.AlertClosed}
	out := make([]pg.AlertStatus, 0, len(candidates))
	for _, c := range candidates {
		if pg.IsValidAlertTransition(from, c) {
			out = append(out, c)
		}
	}
	return out
}

// nextCursorURL builds the next-page URL string the list view links
// to. Empty when no cursor — the template treats that as "last page".
func nextCursorURL(status pg.AlertStatus, hostID string, cursor pg.AlertCursor) string {
	if cursor.AlertID == "" {
		return ""
	}
	return views.AlertsURLWithCursor(status, hostID, cursor)
}
