package v1

import "net/http"

// healthz is the unauthenticated liveness probe. Distinct from the
// HTML console's /healthz so an API consumer never sees an HTML
// body. Returns {"ok": true} with 200 when reachable; the underlying
// pg/ch dependencies are NOT probed here — Phase 6 keeps the JSON
// API liveness check shallow so a slow CH doesn't cascade into an
// API outage. Operators wanting a deep healthcheck use the HTML
// console's /healthz.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
