package console

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/detect"
	"github.com/t3rmit3/slither/server/internal/graph"
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

// hostsProcessTree renders /hosts/{host_id}/process-tree.
//
// Inputs (query string): pid (required, > 0), depth (optional, default
// 4, 1..8). Renders a depth-bounded process tree built from CH
// process_activity. SVG is cached on disk + in memory keyed on
// (host_id, root_pid, depth) — distinct namespace from #64's alert
// keys.
//
// 400 on bad pid/depth; the page itself surfaces "process not found"
// inline rather than 404'ing because the operator just submitted a
// form and a flash on the same page is better UX than a redirect.
func (s *Server) hostsProcessTree(w http.ResponseWriter, r *http.Request) {
	if s.processTreeBuilder == nil || s.graphCache == nil {
		http.NotFound(w, r)
		return
	}
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

	q := r.URL.Query()
	depth := 4
	if d := strings.TrimSpace(q.Get("depth")); d != "" {
		v, perr := strconv.Atoi(d)
		if perr != nil || v < 1 || v > 8 {
			http.Error(w, "bad depth", http.StatusBadRequest)
			return
		}
		depth = v
	}

	data := views.ProcessTreeData{
		Host:   hostLabel(host),
		HostID: host.ID,
		Depth:  depth,
	}

	pidStr := strings.TrimSpace(q.Get("pid"))
	if pidStr == "" {
		// Initial visit — render the form only; SVG comes after submit.
		render(w, r, views.ProcessTree(data))
		return
	}
	pid, perr := strconv.ParseUint(pidStr, 10, 32)
	if perr != nil || pid == 0 {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	data.Pid = uint32(pid)

	key := detect.ProcessTreeCacheKey(host.ID, data.Pid, depth)
	if svg, ok := s.graphCache.Get(key); ok {
		data.SVG = string(svg)
		render(w, r, views.ProcessTree(data))
		return
	}

	source, err := s.processTreeBuilder.Build(r.Context(), host.ID, data.Pid, depth, time.Time{})
	if err != nil {
		http.Error(w, "build process tree failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if source == "" {
		data.Error = "Process not found in CH retention window."
		render(w, r, views.ProcessTree(data))
		return
	}
	data.Truncated = strings.Contains(source, "truncated:")

	svg, err := graph.Render(r.Context(), source)
	if err != nil {
		http.Error(w, "render process tree failed", http.StatusInternalServerError)
		return
	}
	if err := s.graphCache.Put(key, svg); err != nil {
		_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
			ActorType: pg.ActorSystem,
			Action:    "host.process_tree.cache_write_failed",
			Detail: map[string]any{
				"host_id": host.ID,
				"err":     err.Error(),
			},
		})
	}
	data.SVG = string(svg)
	render(w, r, views.ProcessTree(data))
}

// hostLabel picks the most useful display string for a host: hostname
// when present, falls back to the UUID.
func hostLabel(h pg.HostRow) string {
	if h.Hostname != "" {
		return h.Hostname
	}
	return h.ID
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
