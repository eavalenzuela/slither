// Package v1 implements the Phase 6 #120 read-only JSON API mounted
// under /api/v1/. Bearer-token-authenticated, contract-frozen, served
// alongside the HTML console on the same listener.
//
// ADR-0040 locks the surface. Handlers stay log-and-defensive: any
// 4xx/5xx returns the canonical {"error", "message"} JSON body the
// apiauth middleware emits, never an HTML page.

package v1

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/apiauth"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// Server bundles every dependency the v1 handlers need. New
// constructs the routed sub-mux for mounting under /api/v1.
type Server struct {
	pg *pg.Store
	ch *ch.Store
}

// New returns the v1 sub-router. Bearer-token middleware wraps every
// route except /healthz so an external monitor can liveness-poll
// without minting a key.
func New(pgStore *pg.Store, chStore *ch.Store) *Server {
	return &Server{pg: pgStore, ch: chStore}
}

// Mount registers the routes onto a parent chi router under prefix
// (typically /api/v1).
func (s *Server) Mount(r chi.Router) {
	// Unauthenticated.
	r.Get("/healthz", s.healthz)

	// Authenticated subtree.
	r.Group(func(g chi.Router) {
		g.Use(apiauth.Middleware(s.pg))
		g.Post("/events/search", s.eventsSearch)
		g.Get("/events/search", s.eventsSearch) // GET form for curl/dev convenience
		if s.pg != nil {
			g.Get("/rules", s.rulesList)
		}
	})
}

// writeJSON is the success-path response writer. content-type +
// status + body in one call so handlers stay short. status is
// always 200 today; the parameter is reserved for a future Phase
// 7 endpoint that wants 201 on POST-create.
func writeJSON(w http.ResponseWriter, status int, body any) { //nolint:unparam // status reserved for Phase 7 POST-create
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = jsonEncode(w, body)
}
