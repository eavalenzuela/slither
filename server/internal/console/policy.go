package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/respond"
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

// responseActionAudit renders the per-action audit chain for
// forensics. Phase 4 #76. Reads response_actions for the row + the
// reverse chain via parent_action, plus audit_log entries for
// target_kind=response_action target_id=<action_id>. One page tells
// you who issued an action, when it transitioned through each state,
// who reverted it, and the chain forward + backward.
func (s *Server) responseActionAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "action_id")
	if id == "" {
		http.Error(w, "missing action_id", http.StatusBadRequest)
		return
	}
	row, err := s.store.GetResponseAction(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrResponseActionNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load action failed", http.StatusInternalServerError)
		return
	}

	// Audit_log entries for this action — newest first per
	// ListAuditByTarget's ORDER BY id DESC.
	auditRows, err := s.store.ListAuditByTarget(r.Context(),
		"response_action", row.ID, 100)
	if err != nil {
		// Best-effort — render the page with the row even if audit
		// lookup blipped, rather than 500-ing the operator out.
		auditRows = nil
	}

	// Reverse chain: any row with parent_action = row.ID. ListResponseActions
	// scopes by host_id; we filter client-side since per-host is small in
	// practice and avoids a new pg helper for one call site.
	hostHistory, _ := s.store.ListResponseActions(r.Context(), row.HostID, 200)
	related := make([]pg.ResponseActionRow, 0, 4)
	hasChildRevert := false
	for _, h := range hostHistory {
		if h.ParentAction == row.ID || h.ID == row.ParentAction {
			related = append(related, h)
		}
		// A non-terminal-failed child with parent_action=row.ID means
		// a revert is already in flight or completed; suppress the
		// button so the operator doesn't accidentally double-revert.
		if h.ParentAction == row.ID && h.Status != pg.ResponseStatusFailed {
			hasChildRevert = true
		}
	}

	canRevert := false
	if row.Status == pg.ResponseStatusDone && !hasChildRevert {
		switch row.Action {
		case pg.ResponseActionQuarantineFile, pg.ResponseActionIsolateHost:
			canRevert = true
		}
	}

	render(w, r, views.ResponseActionAudit(views.ResponseActionAuditData{
		Action:    row,
		Audit:     auditRows,
		Related:   related,
		CanRevert: canRevert,
	}))
}

// alertRespond accepts a POST from the alert detail's response
// action buttons, validates the action against the host policy, and
// hands it off to respond.Hub.Dispatch. Phase 4 #75. Form fields:
//
//	action  one of pg.ResponseAction values
//	target  the resolved target (PID / path / host_id). The
//	        operator types this when prompted, or it pre-fills from
//	        the alert when the action class has an unambiguous default.
//	reason  optional one-line note carried into the audit row's reason_code
//
// Routing wraps this in RequireRole(analyst, admin) at registration,
// so this handler trusts that the user has *some* response role; the
// per-action permission gate is enforced inside Dispatch via
// pg.HostPolicy.PermitsAction.
func (s *Server) alertRespond(w http.ResponseWriter, r *http.Request) {
	if s.responseHub == nil {
		http.Error(w, "response dispatcher not configured", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := pg.ResponseAction(strings.TrimSpace(r.PostFormValue("action")))
	target := strings.TrimSpace(r.PostFormValue("target"))
	if target == "" {
		target = strings.TrimSpace(r.PostFormValue("default_target"))
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))

	alert, err := s.store.GetAlert(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAlertNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "load alert failed", http.StatusInternalServerError)
		return
	}

	row, dispatchErr := s.responseHub.Dispatch(r.Context(), respond.DispatchInput{
		HostID:     alert.HostID,
		AlertID:    alert.ID,
		Action:     action,
		Target:     target,
		OperatorID: s.userID(r),
		Reason:     reason,
	})
	switch {
	case errors.Is(dispatchErr, respond.ErrPolicyDenied):
		// Row was still written with status=denied_by_policy so the
		// audit chain captures the attempt; surface a flash to the
		// operator and bounce back to the alert detail.
		s.sm.Put(r.Context(), "flash",
			"Action denied by host policy. An admin can promote the host on its policy page.")
		http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
		return
	case dispatchErr != nil:
		http.Error(w, "dispatch failed: "+dispatchErr.Error(), http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), "flash",
		"Dispatched "+string(action)+" (action "+row.ID[:8]+"); see history for status.")
	http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
}

// responseActionRevert handles POST /responses/{action_id}/revert.
// Phase 4 #85. Wraps Hub.Revert with the same flash + redirect shape
// as alertRespond. Wrapped in RequireRole(analyst, admin) at route
// registration; per-action policy is enforced inside Hub.Revert.
func (s *Server) responseActionRevert(w http.ResponseWriter, r *http.Request) {
	if s.responseHub == nil {
		http.Error(w, "response dispatcher not configured", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "action_id")
	if id == "" {
		http.Error(w, "missing action_id", http.StatusBadRequest)
		return
	}

	row, err := s.responseHub.Revert(r.Context(), id, s.userID(r))
	switch {
	case errors.Is(err, respond.ErrNotReversible):
		s.sm.Put(r.Context(), "flash", "This action class is not reversible.")
		http.Redirect(w, r, "/responses/"+id+"/audit", http.StatusSeeOther)
		return
	case errors.Is(err, respond.ErrParentNotDone):
		s.sm.Put(r.Context(), "flash",
			"Only completed actions (status=done) can be reverted.")
		http.Redirect(w, r, "/responses/"+id+"/audit", http.StatusSeeOther)
		return
	case errors.Is(err, respond.ErrPolicyDenied):
		s.sm.Put(r.Context(), "flash",
			"Revert denied by host policy. An admin can promote the host on its policy page.")
		http.Redirect(w, r, "/responses/"+id+"/audit", http.StatusSeeOther)
		return
	case err != nil:
		http.Error(w, "revert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), "flash",
		"Revert dispatched (action "+row.ID[:8]+"); see history for status.")
	http.Redirect(w, r, "/responses/"+row.ID+"/audit", http.StatusSeeOther)
}
