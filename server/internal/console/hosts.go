package console

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// hostsHeartbeatTTL is the cadence used to derive online/stale/offline
// status. Matches the agent's default heartbeat interval (#35);
// changing the agent default means changing this too. Phase 5 will
// surface this via config so operators with custom cadences see
// accurate status.
const hostsHeartbeatTTL = 30 * time.Second

func (s *Server) hostsList(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		http.Error(w, "list hosts failed", http.StatusInternalServerError)
		return
	}
	render(w, r, views.Hosts(views.HostsPageData{
		Hosts:        hosts,
		Now:          time.Now().UTC(),
		HeartbeatTTL: hostsHeartbeatTTL,
		IsAdmin:      s.role(r) == pg.RoleAdmin,
	}))
}

// hostsRevoke handles POST /hosts/{host_id}/revoke. The route is
// already wrapped in RequireRole(admin) at registration; this handler
// trusts the role check and focuses on the DB op + audit trail.
func (s *Server) hostsRevoke(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")
	if hostID == "" {
		http.Error(w, "missing host_id", http.StatusBadRequest)
		return
	}
	switch err := s.store.RevokeHost(r.Context(), hostID, s.userID(r)); {
	case errors.Is(err, pg.ErrHostNotFound):
		http.Error(w, "host not found or already revoked", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/hosts", http.StatusSeeOther)
}
