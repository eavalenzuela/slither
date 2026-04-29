package console

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// hostsPolicyEdit renders /hosts/{host_id}/policy. Admin-only by
// route registration in console.go. Loads the host row + the
// existing policy; an unset policy resolves to detect-only via
// pg.GetHostPolicy's missing-row → zero-value contract.
func (s *Server) hostsPolicyEdit(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")
	if hostID == "" {
		http.Error(w, "missing host_id", http.StatusBadRequest)
		return
	}
	host, err := s.store.GetHost(r.Context(), hostID)
	switch {
	case errors.Is(err, pg.ErrHostNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load host failed", http.StatusInternalServerError)
		return
	}
	policy, err := s.store.GetHostPolicy(r.Context(), hostID)
	if err != nil {
		http.Error(w, "load policy failed", http.StatusInternalServerError)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.HostPolicy(views.HostPolicyData{
		Host:    host,
		Policy:  policy,
		Flash:   flash,
		IsAdmin: true,
	}))
}

// hostsPolicyUpdate handles POST /hosts/{host_id}/policy. Wraps the
// upsert in the audit chain pg.UpsertHostPolicy already maintains so
// the operator's edit is visible in audit_log. The handler is
// admin-only by route registration.
func (s *Server) hostsPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")
	if hostID == "" {
		http.Error(w, "missing host_id", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	policy := pg.HostPolicy{
		HostID:           hostID,
		AllowKillProcess: r.PostFormValue("allow_kill_process") == "on",
		AllowKillTree:    r.PostFormValue("allow_kill_tree") == "on",
		AllowQuarantine:  r.PostFormValue("allow_quarantine") == "on",
		AllowIsolate:     r.PostFormValue("allow_isolate") == "on",
		AllowCollect:     r.PostFormValue("allow_collect") == "on",
	}

	if _, err := s.store.UpsertHostPolicy(r.Context(), policy, s.userID(r)); err != nil {
		http.Error(w, "save policy failed", http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), "flash", "Policy updated.")
	http.Redirect(w, r, "/hosts/"+hostID+"/policy", http.StatusSeeOther)
}

// alertRespondStub returns 501 Not Implemented for now. The full
// dispatcher path lands in #75 (server/internal/respond/). Buttons
// rendered by the alert detail page hit this endpoint; until #75
// fills the body we reject with a clear message instead of letting
// the form 404 silently.
func (s *Server) alertRespondStub(w http.ResponseWriter, r *http.Request) {
	http.Error(w,
		"response dispatch not yet implemented (lands in Phase 4 #75)",
		http.StatusNotImplemented)
}
