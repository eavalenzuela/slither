// Phase 6 #115 — per-user dashboards.
//
// A dashboard is a user-owned collection of cards; each card
// references one /queries row by id. The dashboard render path
// resolves each card's saved-query and shows a count + top-N
// preview. Deleted saved queries surface as a "(query deleted)"
// placeholder card so a dashboard isn't poisoned by a stale id.
//
// v1 layout shape: a flat array of cards in render order. Card-add
// and card-remove are atomic UpdateDashboardLayout writes (full
// layout replace). No drag-to-reorder, no resize — Phase 7+ if
// demand justifies it.
//
// Card preview: rendered by the surface that owns the saved query.
// Phase 6 ships only a count summary (count of rows the saved
// filter would return on the source surface). The top-N list lands
// once #116's events query language gives us a faster surface to
// hit; for now operators click through to the underlying surface
// for the row data.

package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func (s *Server) dashboardsList(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rows, err := s.store.ListDashboards(r.Context(), userID, 200)
	if err != nil {
		http.Error(w, "list dashboards failed", http.StatusInternalServerError)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.DashboardsList(views.DashboardsListData{
		Dashboards: rows,
		Flash:      flash,
	}))
}

func (s *Server) dashboardsCreate(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 200 {
		http.Error(w, "name required (≤200 chars)", http.StatusBadRequest)
		return
	}
	id, err := s.store.InsertDashboard(r.Context(), userID, name)
	if errors.Is(err, pg.ErrDashboardExists) {
		s.sm.Put(r.Context(), "flash", "A dashboard with that name already exists.")
		http.Redirect(w, r, "/dashboards", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "dashboard.created",
		TargetKind: "dashboard",
		TargetID:   id,
		Detail:     map[string]any{"name": name},
	})
	http.Redirect(w, r, "/dashboards/"+id, http.StatusSeeOther)
}

func (s *Server) dashboardsDetail(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	d, err := s.store.GetDashboard(r.Context(), userID, id)
	switch {
	case errors.Is(err, pg.ErrDashboardNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load dashboard failed", http.StatusInternalServerError)
		return
	}

	// Resolve every card's saved-query. A missing reference (operator
	// deleted the saved query elsewhere) surfaces as a "(query
	// deleted)" placeholder rather than tearing down the page.
	resolved := make([]views.DashboardCardResolved, 0, len(d.Cards))
	for _, c := range d.Cards {
		card := views.DashboardCardResolved{
			QueryID: c.QueryID,
			Label:   c.Label,
		}
		q, qerr := s.store.GetSavedQuery(r.Context(), userID, c.QueryID)
		if errors.Is(qerr, pg.ErrSavedQueryNotFound) {
			card.Deleted = true
		} else if qerr != nil {
			// Treat lookup error as deleted so the page renders; the
			// audit log captures the underlying error.
			card.Deleted = true
		} else {
			card.Query = q
			card.URL = EncodeSavedQueryURL(q)
		}
		resolved = append(resolved, card)
	}

	// Build the user's saved-query list as the "add card" picker.
	all, _ := s.store.ListSavedQueries(r.Context(), userID, 200)

	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.DashboardDetail(views.DashboardDetailData{
		Dashboard:    d,
		Cards:        resolved,
		AvailableSQs: all,
		Flash:        flash,
	}))
}

func (s *Server) dashboardsAddCard(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	d, err := s.store.GetDashboard(r.Context(), userID, id)
	switch {
	case errors.Is(err, pg.ErrDashboardNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load dashboard failed", http.StatusInternalServerError)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	queryID := strings.TrimSpace(r.PostFormValue("query_id"))
	label := strings.TrimSpace(r.PostFormValue("label"))
	if queryID == "" {
		http.Error(w, "query_id required", http.StatusBadRequest)
		return
	}
	if _, qerr := s.store.GetSavedQuery(r.Context(), userID, queryID); qerr != nil {
		http.Error(w, "saved query not found for this user", http.StatusBadRequest)
		return
	}
	cards := append([]pg.DashboardCard(nil), d.Cards...)
	cards = append(cards, pg.DashboardCard{QueryID: queryID, Label: label})
	if err := s.store.UpdateDashboardLayout(r.Context(), userID, id, cards); err != nil {
		http.Error(w, "update layout failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "dashboard.card_added",
		TargetKind: "dashboard",
		TargetID:   id,
		Detail:     map[string]any{"query_id": queryID},
	})
	http.Redirect(w, r, "/dashboards/"+id, http.StatusSeeOther)
}

func (s *Server) dashboardsRemoveCard(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	queryID := chi.URLParam(r, "query_id")
	d, err := s.store.GetDashboard(r.Context(), userID, id)
	switch {
	case errors.Is(err, pg.ErrDashboardNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load dashboard failed", http.StatusInternalServerError)
		return
	}
	cards := make([]pg.DashboardCard, 0, len(d.Cards))
	for _, c := range d.Cards {
		if c.QueryID == queryID {
			continue
		}
		cards = append(cards, c)
	}
	if err := s.store.UpdateDashboardLayout(r.Context(), userID, id, cards); err != nil {
		http.Error(w, "update layout failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "dashboard.card_removed",
		TargetKind: "dashboard",
		TargetID:   id,
		Detail:     map[string]any{"query_id": queryID},
	})
	http.Redirect(w, r, "/dashboards/"+id, http.StatusSeeOther)
}

func (s *Server) dashboardsDelete(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	err := s.store.DeleteDashboard(r.Context(), userID, id)
	switch {
	case errors.Is(err, pg.ErrDashboardNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "dashboard.deleted",
		TargetKind: "dashboard",
		TargetID:   id,
	})
	http.Redirect(w, r, "/dashboards", http.StatusSeeOther)
}
