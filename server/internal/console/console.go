// Package console hosts the HTMX operator UI. Phase 2 §4.1 task #41:
// chi router, scs session manager backed by Postgres, argon2id-verified
// login, and route-level RBAC. Live tail / events / hosts / alerts
// pages land in #42–#44 hanging nav off the same layout shell.
//
// RBAC is endpoint-only in v1 per IMPLEMENTATION.md §4 — row-level
// scoping (which alerts an analyst can ack) waits for Phase 3 once
// real multi-team deployments justify the column work in Postgres.
package console

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/t3rmit3/slither/server/internal/console/static"
	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/detect"
	"github.com/t3rmit3/slither/server/internal/graph"
	"github.com/t3rmit3/slither/server/internal/hunt"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/respond"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// Options bundle the dependencies the console needs. Store is required;
// SessionKey is the 64-byte secret HMAC key used to sign session
// cookies and rotate to a new key file on startup if missing. Bus is
// optional — pass it to enable the live-tail SSE page (#42); leaving
// it nil hides the route. ChStore is optional — pass it to enable the
// events search page (#43). DefaultEnrollServer is the host:port the
// /enrolment-tokens page renders into the copy-paste enroll command
// (#45); empty value falls back to "<server>:9444".
type Options struct {
	Store               *pg.Store
	Telem               *telemetry.Counters
	Bus                 *ingest.Bus
	ChStore             *ch.Store
	SessionKey          []byte
	SessionTimeout      time.Duration
	DefaultEnrollServer string
	// GraphCache is the on-disk + in-memory SVG cache feeding the
	// alert flow-graph render path (#64). Optional — when nil, the
	// detail page omits the graph block entirely so the console
	// still works on hosts without a writable StateDirectory.
	GraphCache *graph.Cache
	// ResponseHub dispatches operator-driven response actions onto
	// per-host send queues (Phase 4 #75). Optional — when nil, the
	// alert response button POST returns 503 cleanly rather than
	// trying to dispatch.
	ResponseHub *respond.Hub
	// HuntHub dispatches operator-driven live-query hunts onto
	// per-host send queues (Phase 6 #110). Optional — when nil the
	// /hunt POST returns 503 and the page renders read-only history.
	HuntHub *hunt.Hub

	// ArtefactDir is the same dir the response dispatcher writes
	// COLLECT_ARTIFACTS + Phase 6 #111 snapshot blobs to. The alert
	// detail page lists per-extension snapshots under
	// <ArtefactDir>/<alert_id>/*.tgz. Empty disables the listing
	// (alerts still render; the snapshot block is hidden).
	ArtefactDir string

	// OIDC, when populated and successfully discovered, enables
	// Phase 6 #113 SSO. New routes /oidc/login + /oidc/callback are
	// registered; the /login page renders an extra "Sign in with
	// SSO" button. Empty leaves SSO off; partial config fails
	// console.Validate at boot.
	OIDC ConsoleOIDC
}

// ConsoleOIDC mirrors config.ConsoleOIDC at the package boundary so
// the console package doesn't import the config package directly. The
// app wires the conversion in server/internal/app/app.go.
type ConsoleOIDC struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	RoleClaim     string
	RoleMappings  map[string]string
	UsernameClaim string
}

// Enabled reports whether enough fields are populated to wire SSO
// routes. Mirrors config.ConsoleOIDC.Enabled.
func (c ConsoleOIDC) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// Server is the chi.Router built around Options. New returns a stdlib
// http.Handler ready to be plugged into app.Run's console listener.
type Server struct {
	store               *pg.Store
	telem               *telemetry.Counters
	bus                 *ingest.Bus
	chStore             *ch.Store
	sm                  *scs.SessionManager
	mux                 *chi.Mux
	defaultEnrollServer string
	graphCache          *graph.Cache
	graphBuilder        *detect.FlowGraphBuilder
	processTreeBuilder  *detect.ProcessTreeBuilder
	processTreeJSON     *detect.ProcessTreeJSONBuilder
	responseHub         *respond.Hub
	huntHub             *hunt.Hub
	artefactDir         string
	oidc                *oidcAuth
}

// New constructs the console router. Panics on misconfiguration — a
// console without a session key cannot meaningfully run.
func New(opts Options) *Server {
	if opts.Store == nil {
		panic("console.New: nil store")
	}
	if opts.Telem == nil {
		opts.Telem = telemetry.NewCounters()
	}
	if len(opts.SessionKey) < 32 {
		panic("console.New: session key must be at least 32 bytes")
	}
	if opts.SessionTimeout <= 0 {
		opts.SessionTimeout = 12 * time.Hour
	}

	sm := scs.New()
	sm.Store = pgxstore.New(opts.Store.Pool())
	sm.Lifetime = opts.SessionTimeout
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	// Don't set Secure here — the compose stack puts the console
	// behind HTTP for dev. Production deployments terminate TLS at a
	// reverse proxy and should set this in a config wrapper later.

	s := &Server{
		store:               opts.Store,
		telem:               opts.Telem,
		bus:                 opts.Bus,
		chStore:             opts.ChStore,
		sm:                  sm,
		mux:                 chi.NewRouter(),
		defaultEnrollServer: opts.DefaultEnrollServer,
		graphCache:          opts.GraphCache,
		responseHub:         opts.ResponseHub,
		huntHub:             opts.HuntHub,
		artefactDir:         opts.ArtefactDir,
	}
	if opts.OIDC.Enabled() {
		auth, err := initOIDC(context.Background(), oidcConfig{
			IssuerURL:     opts.OIDC.IssuerURL,
			ClientID:      opts.OIDC.ClientID,
			ClientSecret:  opts.OIDC.ClientSecret,
			RedirectURL:   opts.OIDC.RedirectURL,
			Scopes:        opts.OIDC.Scopes,
			RoleClaim:     opts.OIDC.RoleClaim,
			RoleMappings:  opts.OIDC.RoleMappings,
			UsernameClaim: opts.OIDC.UsernameClaim,
		})
		if err != nil {
			// Discovery failure logs + leaves SSO off; the operator
			// fixes the IdP and restarts. Refusing boot would lock
			// every operator out of the console for a transient IdP
			// blip.
			slog.Warn("console: OIDC discovery failed; SSO disabled",
				"issuer", opts.OIDC.IssuerURL, "err", err)
		} else {
			s.oidc = auth
		}
	}
	if opts.GraphCache != nil && opts.ChStore != nil {
		s.graphBuilder = &detect.FlowGraphBuilder{Lookup: opts.ChStore}
		s.processTreeBuilder = &detect.ProcessTreeBuilder{Lookup: opts.ChStore}
	}
	// Phase 6 #114 — live process-tree JSON builder. Independent of
	// the GraphCache (the explorer renders client-side, no SVG cache
	// hop) so it lights up with just ChStore.
	if opts.ChStore != nil {
		s.processTreeJSON = &detect.ProcessTreeJSONBuilder{Lookup: opts.ChStore}
	}
	s.routes()
	return s
}

// Handler returns the wrapped router with the session middleware
// applied — this is what app.Run mounts on the console listener.
func (s *Server) Handler() http.Handler {
	return s.sm.LoadAndSave(s.mux)
}

// Mux exposes the underlying chi.Mux so #42–#44 can register their
// pages on the same router under the same auth + session middleware.
func (s *Server) Mux() *chi.Mux { return s.mux }

func (s *Server) routes() {
	s.mux.Use(middleware.Recoverer)
	s.mux.Use(middleware.RealIP)

	// Static + healthcheck are unauthenticated.
	s.mux.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS()))))
	s.mux.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	s.mux.Get("/login", s.loginPage)
	s.mux.Post("/login", s.loginSubmit)
	s.mux.Post("/logout", s.logout)
	// Phase 6 #113 SSO routes — registered only when OIDC is wired
	// (discovery succeeded at boot). Both routes 404 cleanly when
	// SSO is off; the /login page hides the SSO button to match.
	if s.oidc != nil {
		s.mux.Get("/oidc/login", s.oidcLogin)
		s.mux.Get("/oidc/callback", s.oidcCallback)
	}

	// Authenticated routes — viewer is the lowest bar; per-page roles
	// are enforced inside the handlers when a stricter role is needed
	// (e.g., the rule editor in #42 is admin-only).
	s.mux.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Get("/", redirectTo("/dashboard"))
		r.Get("/dashboard", s.dashboard)
		if s.bus != nil {
			r.Get("/live", s.livePage)
			r.Get("/live/stream", s.liveStream)
		}
		if s.chStore != nil {
			r.Get("/events", s.eventsList)
			r.Get("/events/{class_uid}/{event_id}", s.eventDetail)
		}
		r.Get("/hosts", s.hostsList)
		if s.processTreeBuilder != nil {
			r.Get("/hosts/{host_id}/process-tree", s.hostsProcessTree)
		}
		// Phase 6 #112 — chain-summary status page. Lists the most
		// recent chain summaries the host emitted and any mismatch
		// history. No role gate beyond viewer.
		r.Get("/hosts/{host_id}/chain-status", s.hostsChainStatus)
		r.With(s.RequireRole(pg.RoleAdmin)).
			Post("/hosts/{host_id}/revoke", s.hostsRevoke)
		// Phase 4 #74: per-host response policy editor (admin-only).
		r.With(s.RequireRole(pg.RoleAdmin)).Group(func(r chi.Router) {
			r.Get("/hosts/{host_id}/policy", s.hostsPolicyEdit)
			r.Post("/hosts/{host_id}/policy", s.hostsPolicyUpdate)
		})

		// Phase 4 #75: alert response action dispatch. The handler
		// validates the action against pg.HostPolicy and hands off
		// to respond.Hub.Dispatch. Wrapped in
		// RequireRole(analyst,admin); the per-action permission
		// gate lives inside Dispatch.
		r.With(s.RequireRole(pg.RoleAnalyst, pg.RoleAdmin)).
			Post("/alerts/{id}/respond", s.alertRespond)

		// Alerts (Phase 3 #61). List + detail are viewer-readable;
		// transitions require analyst or admin.
		r.Get("/alerts", s.alertsList)
		r.Get("/alerts/{id}", s.alertDetail)
		r.With(s.RequireRole(pg.RoleAnalyst, pg.RoleAdmin)).
			Post("/alerts/{id}/transition", s.alertTransition)
		if s.graphBuilder != nil {
			r.Get("/alerts/{id}/graph.svg", s.alertGraph)
		}
		// Phase 6 #114 — live process-tree explorer. JSON endpoint
		// the client SVG renderer fetches; lazy-loads expansions by
		// re-calling with a different root_pid.
		if s.processTreeJSON != nil {
			r.Get("/alerts/{id}/process-tree.json", s.alertProcessTreeJSON)
		}
		// Phase 6 #111 — per-extension snapshot blob download. Reads
		// from <artefactDir>/<alert_id>/<extension>.tgz; 404s if the
		// dir or file is missing or if either path component fails
		// the safe-name check.
		if s.artefactDir != "" {
			r.Get("/alerts/{id}/snapshots/{extension}", s.alertSnapshotDownload)
		}
		// Phase 4 #76: forensics drill-down for the response chain
		// against an action. Reads audit_log filtered to
		// target_kind=response_action; the chain (pending → running
		// → done/failed, plus reverted-by linkage) lands as one
		// page per action_id.
		r.Get("/responses/{action_id}/audit", s.responseActionAudit)

		// Phase 4 #85: revert a completed response action. Hub.Revert
		// validates reversibility + host policy + parent state; the
		// route gate just keeps it analyst+ to mirror the dispatch
		// path's role policy.
		r.With(s.RequireRole(pg.RoleAnalyst, pg.RoleAdmin)).
			Post("/responses/{action_id}/revert", s.responseActionRevert)

		// Phase 6 #110: live-query hunts. List + detail are viewer-
		// readable so analysts can review history; dispatch is
		// analyst+admin gated.
		r.Get("/hunt", s.huntList)
		r.Get("/hunt/{id}", s.huntDetail)
		r.Get("/hunt/{id}.csv", s.huntCSV)
		r.With(s.RequireRole(pg.RoleAnalyst, pg.RoleAdmin)).
			Post("/hunt", s.huntDispatch)

		// Enrolment-token UX (#45) — admin-only across the board.
		r.With(s.RequireRole(pg.RoleAdmin)).Group(func(r chi.Router) {
			r.Get("/enrolment-tokens", s.enrolmentTokensList)
			r.Post("/enrolment-tokens", s.enrolmentTokensCreate)
			r.Post("/enrolment-tokens/{token_id}/revoke", s.enrolmentTokensRevoke)
		})

		// IOC feeds (#66) — admin-only CRUD.
		r.With(s.RequireRole(pg.RoleAdmin)).Group(func(r chi.Router) {
			r.Get("/iocs", s.iocsList)
			r.Get("/iocs/new", s.iocsNew)
			r.Post("/iocs/new", s.iocsCreate)
			r.Post("/iocs/{feed_id}/delete", s.iocsDelete)
		})
	})
}

func staticFS() fs.FS {
	sub, err := fs.Sub(static.FS, ".")
	if err != nil {
		panic(err) // build-time embed; impossible at runtime
	}
	return sub
}

func redirectTo(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, path, http.StatusFound)
	}
}

// --- handlers ---

const (
	sessionUserID   = "user_id"
	sessionUsername = "username"
	sessionRole     = "role"
)

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.userID(r) != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	flash, _ := s.sm.Pop(r.Context(), "flash").(string)
	render(w, r, views.Login(views.LoginData{Flash: flash, SSOEnabled: s.oidc != nil}))
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	// Cap form size — login is two short fields; anything bigger is
	// abuse. http.MaxBytesReader is what gosec G120 wants here, and
	// it's a cheap defence regardless.
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	if username == "" || password == "" {
		s.failLogin(r.Context(), username, "empty_field")
		s.sm.Put(r.Context(), "flash", "Username and password are required.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), username)
	switch {
	case errors.Is(err, pg.ErrUserNotFound):
		s.failLogin(r.Context(), username, "unknown_user")
		s.sm.Put(r.Context(), "flash", "Invalid credentials.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !pg.VerifyArgon2id(user.PasswordHash, password) {
		s.failLogin(r.Context(), username, "bad_password")
		s.sm.Put(r.Context(), "flash", "Invalid credentials.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// scs guidance: rotate the session token on privilege change to
	// prevent fixation. This also wipes any pre-login state.
	if err := s.sm.RenewToken(r.Context()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.sm.Put(r.Context(), sessionUserID, user.ID)
	s.sm.Put(r.Context(), sessionUsername, user.Username)
	s.sm.Put(r.Context(), sessionRole, string(user.Role))

	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType: pg.ActorUser,
		ActorID:   user.ID,
		Action:    "auth.login.success",
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(r)
	_ = s.sm.Destroy(r.Context())
	if uid != "" {
		_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
			ActorType: pg.ActorUser,
			ActorID:   uid,
			Action:    "auth.logout",
		})
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	render(w, r, views.Dashboard(views.DashboardData{
		Username: s.username(r),
		Role:     s.role(r),
	}))
}

// --- auth + RBAC ---

// requireAuth redirects to /login when the request has no user_id in
// the session. Used as a middleware on the authenticated route group.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.userID(r) == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole returns middleware that 403s when the session role isn't
// in the allowed list. Exposed (capital R) so #42–#44 page handlers
// can wrap their admin-only actions (rule editor, host revoke, ...).
func (s *Server) RequireRole(roles ...pg.UserRole) func(http.Handler) http.Handler {
	allowed := make(map[pg.UserRole]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := allowed[s.role(r)]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) userID(r *http.Request) string {
	v, _ := s.sm.Get(r.Context(), sessionUserID).(string)
	return v
}

func (s *Server) username(r *http.Request) string {
	v, _ := s.sm.Get(r.Context(), sessionUsername).(string)
	return v
}

func (s *Server) role(r *http.Request) pg.UserRole {
	v, _ := s.sm.Get(r.Context(), sessionRole).(string)
	return pg.UserRole(v)
}

// failLogin records a failed-login audit row. Best-effort — a DB blip
// here cannot block the user-facing redirect.
func (s *Server) failLogin(ctx context.Context, username, reason string) {
	s.telem.IncAuthnFailure()
	_ = s.store.LogAudit(ctx, pg.AuditEntry{
		ActorType: pg.ActorUser,
		Action:    "auth.login.failure",
		Detail: map[string]any{
			"username": username,
			"reason":   reason,
		},
	})
}

// render writes a templ.Component to w with the HTML content-type set.
func render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = c.Render(r.Context(), w)
}
