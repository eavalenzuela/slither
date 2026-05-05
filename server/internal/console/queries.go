// Phase 6 #115 — saved queries page.
//
// The /events, /alerts, and /hunt list pages each gain a "Save"
// button (rendered in their existing filter forms) that POSTs the
// current URL query string + a user-supplied name to /queries.
// The /queries page lists the user's saved queries and links each
// back to its origin surface with the captured params re-encoded
// onto the URL.
//
// All routes are user-scoped: queries belong to the session user;
// no shared queries in v1 (ADR-0037).

package console

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// queriesList renders /queries — the user's saved-query inventory.
func (s *Server) queriesList(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rows, err := s.store.ListSavedQueries(r.Context(), userID, 200)
	if err != nil {
		http.Error(w, "list saved queries failed", http.StatusInternalServerError)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.SavedQueries(views.SavedQueriesData{
		Queries: rows,
		Flash:   flash,
	}))
}

// queriesCreate handles the Save button POST. Inputs:
//   - name: required, ≤200 chars
//   - surface: required, one of events/alerts/hunts
//   - params: the URL-encoded query string from the source page (the
//     filter form ships its current querystring as a hidden field).
func (s *Server) queriesCreate(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	surface := pg.SavedQuerySurface(strings.TrimSpace(r.PostFormValue("surface")))
	params := strings.TrimSpace(r.PostFormValue("params"))
	if name == "" || len(name) > 200 {
		http.Error(w, "name required (≤200 chars)", http.StatusBadRequest)
		return
	}
	switch surface {
	case pg.SavedQuerySurfaceEvents, pg.SavedQuerySurfaceAlerts, pg.SavedQuerySurfaceHunts:
	default:
		http.Error(w, "invalid surface", http.StatusBadRequest)
		return
	}
	parsed, perr := url.ParseQuery(params)
	if perr != nil {
		http.Error(w, "bad params", http.StatusBadRequest)
		return
	}
	flat := flattenParams(parsed)

	id, err := s.store.InsertSavedQuery(r.Context(), pg.SavedQueryInsert{
		UserID:  userID,
		Name:    name,
		Surface: surface,
		Params:  flat,
	})
	if errors.Is(err, pg.ErrSavedQueryExists) {
		s.sm.Put(r.Context(), "flash", "A saved query with that name already exists for this surface.")
		http.Redirect(w, r, "/queries", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "query.saved",
		TargetKind: "saved_query",
		TargetID:   id,
		Detail: map[string]any{
			"surface": string(surface),
			"name":    name,
		},
	})
	s.sm.Put(r.Context(), "flash", "Saved query \""+name+"\".")
	http.Redirect(w, r, "/queries", http.StatusSeeOther)
}

// queriesDelete handles POST /queries/{id}/delete. Best-effort —
// deleting a query that's referenced by a dashboard card leaves a
// dangling id that the dashboard renderer surfaces as
// "(query deleted)" per the spec.
func (s *Server) queriesDelete(w http.ResponseWriter, r *http.Request) {
	userID := s.userID(r)
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	err := s.store.DeleteSavedQuery(r.Context(), userID, id)
	switch {
	case errors.Is(err, pg.ErrSavedQueryNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    userID,
		Action:     "query.deleted",
		TargetKind: "saved_query",
		TargetID:   id,
	})
	http.Redirect(w, r, "/queries", http.StatusSeeOther)
}

// flattenParams collapses url.Values (multi-value-per-key) into the
// single-value-per-key shape pg.SavedQuery.Params stores. Multi-valued
// filters aren't a Phase 6 concern — every filter form on the source
// pages is single-valued — so the first value wins on the rare
// duplicate.
func flattenParams(v url.Values) map[string]string {
	out := make(map[string]string, len(v))
	for k, vs := range v {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

// EncodeSavedQueryURL builds the round-trip URL for a saved query —
// the surface-specific list page with the captured params re-encoded.
// Exposed so the views package can wire links without re-importing
// url.Values.
func EncodeSavedQueryURL(q pg.SavedQuery) string {
	u := url.Values{}
	for k, v := range q.Params {
		u.Set(k, v)
	}
	enc := u.Encode()
	base := "/" + string(q.Surface)
	if enc == "" {
		return base
	}
	return base + "?" + enc
}
