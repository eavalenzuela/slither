// Phase 6 #113 — Console SSO (OIDC).
//
// Auth-code flow with PKCE, no group sync, no SCIM. The handler sits
// alongside the local password login: when console.oidc is configured,
// the /login page renders an extra "Sign in with SSO" button and the
// OIDC routes register; when it's empty, the routes 404 and the login
// page is unchanged. The bootstrap admin can always log in via local
// credentials so an IdP outage doesn't lock operators out.
//
// User provisioning: first-time sign-in creates a `users` row with
// oidc_subject = ID-token sub claim, username = the configured
// username_claim (default "email"), role from the per-claim-value
// role-mappings table. Subsequent sign-ins match on oidc_subject; a
// claim-value role change refreshes the stored role inline.
//
// Threat model:
//   - State + nonce binding prevent CSRF + token replay.
//   - PKCE binds the code-exchange to the original request's verifier.
//   - The session manager rotates its token after a successful login
//     (matches the local-login path) so a pre-login state cookie can't
//     ride into the post-login session.
//   - Failure paths audit auth.oidc.failure with a reason; success
//     paths audit auth.oidc.success.

package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// oidcInit timeout caps the IdP discovery dial. A slow IdP at boot
// shouldn't stall the server — Init logs the failure and the routes
// stay 404 until the operator restarts after fixing the IdP.
const oidcInitTimeout = 10 * time.Second

// oidcStateTTL bounds how long an OAuth2 state token is valid. 10
// minutes covers a slow IdP login flow without leaving stale state
// cookies usable for replay.
const oidcStateTTL = 10 * time.Minute

// oidcSession key names. scs stamps these into the same encrypted
// session cookie used for post-login state.
const (
	oidcSessionState        = "oidc_state"
	oidcSessionNonce        = "oidc_nonce"
	oidcSessionCodeVerifier = "oidc_code_verifier"
	oidcSessionStateExpiry  = "oidc_state_expiry"
)

// oidcConfig captures the SSO config in the shape the handler uses.
// Decoupled from config.ConsoleOIDC so tests can construct it without
// pulling the YAML loader.
type oidcConfig struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	RoleClaim     string
	RoleMappings  map[string]string
	UsernameClaim string
}

// oidcAuth holds the wired-up provider + verifier the handlers use.
// nil when SSO is disabled.
type oidcAuth struct {
	cfg      oidcConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// initOIDC builds the provider + verifier. Returns nil + nil when
// cfg.IssuerURL is empty (SSO disabled). Discovery errors return nil +
// the error so console.New can log + degrade rather than refuse boot.
func initOIDC(ctx context.Context, cfg oidcConfig) (*oidcAuth, error) {
	if cfg.IssuerURL == "" {
		return nil, nil
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "groups"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "email"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	} else {
		hasOpenID := false
		for _, s := range cfg.Scopes {
			if s == oidc.ScopeOpenID {
				hasOpenID = true
				break
			}
		}
		if !hasOpenID {
			cfg.Scopes = append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
		}
	}

	dctx, cancel := context.WithTimeout(ctx, oidcInitTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(dctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %q: %w", cfg.IssuerURL, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	o := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}
	return &oidcAuth{cfg: cfg, provider: provider, verifier: verifier, oauth: o}, nil
}

// oidcLogin starts the auth-code flow: mints state + PKCE verifier,
// stamps both into the session cookie, redirects the operator to the
// IdP authorisation endpoint with the matching state + code_challenge
// query params.
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	state, err := randURLString(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randURLString(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier, err := randURLString(64)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.sm.Put(r.Context(), oidcSessionState, state)
	s.sm.Put(r.Context(), oidcSessionNonce, nonce)
	s.sm.Put(r.Context(), oidcSessionCodeVerifier, verifier)
	s.sm.Put(r.Context(), oidcSessionStateExpiry, time.Now().Add(oidcStateTTL).Unix())

	challenge := pkceChallenge(verifier)
	authURL := s.oidc.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcCallback finishes the flow: validates state + nonce, exchanges
// the code for a token, verifies the ID token, maps the role claim,
// upserts the users row, and rotates the session token before
// stamping user_id / username / role like the local-login path.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	expectState, _ := s.sm.Get(ctx, oidcSessionState).(string)
	expectNonce, _ := s.sm.Get(ctx, oidcSessionNonce).(string)
	verifier, _ := s.sm.Get(ctx, oidcSessionCodeVerifier).(string)
	expiry, _ := s.sm.Get(ctx, oidcSessionStateExpiry).(int64)

	// Wipe the per-flow state regardless of outcome — a failed login
	// must not leave the same state token usable for a replay.
	s.sm.Remove(ctx, oidcSessionState)
	s.sm.Remove(ctx, oidcSessionNonce)
	s.sm.Remove(ctx, oidcSessionCodeVerifier)
	s.sm.Remove(ctx, oidcSessionStateExpiry)

	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		s.failOIDC(ctx, "", "idp_error", errParam)
		s.sm.Put(ctx, "flash", "Sign-in failed: "+errParam)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	gotState := q.Get("state")
	if expectState == "" || gotState == "" || gotState != expectState {
		s.failOIDC(ctx, "", "state_mismatch", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: state mismatch.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if expiry == 0 || time.Now().Unix() > expiry {
		s.failOIDC(ctx, "", "state_expired", "")
		s.sm.Put(ctx, "flash", "Sign-in flow timed out; please try again.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.failOIDC(ctx, "", "missing_code", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: missing code.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	tok, err := s.oidc.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		s.failOIDC(ctx, "", "exchange_failed", err.Error())
		s.sm.Put(ctx, "flash", "Sign-in failed at the token exchange.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.failOIDC(ctx, "", "no_id_token", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: IdP returned no ID token.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	idToken, verr := s.oidc.verifier.Verify(ctx, rawIDToken)
	if verr != nil {
		s.failOIDC(ctx, "", "id_token_invalid", verr.Error())
		s.sm.Put(ctx, "flash", "Sign-in failed: ID token rejected.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if idToken.Nonce != expectNonce {
		s.failOIDC(ctx, "", "nonce_mismatch", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: nonce mismatch.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var claims map[string]any
	if cerr := idToken.Claims(&claims); cerr != nil {
		s.failOIDC(ctx, "", "claims_decode", cerr.Error())
		s.sm.Put(ctx, "flash", "Sign-in failed: claims decode.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	subject := idToken.Subject
	if subject == "" {
		s.failOIDC(ctx, "", "no_subject", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: ID token missing subject.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	role, mapped := mapOIDCRole(claims, s.oidc.cfg.RoleClaim, s.oidc.cfg.RoleMappings)
	if !mapped {
		s.failOIDC(ctx, subject, "no_role_mapping", "")
		s.sm.Put(ctx, "flash", "Sign-in failed: no role mapping for your IdP groups.")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := stringClaim(claims, s.oidc.cfg.UsernameClaim)
	if username == "" {
		// Fall back to the subject so a row can still be provisioned.
		// Operators set username_claim to whatever's available; the
		// console treats username as a display string after first
		// login.
		username = subject
	}

	user, err := s.store.GetUserByOIDCSubject(ctx, subject)
	switch {
	case errors.Is(err, pg.ErrUserNotFound):
		id, ierr := s.store.InsertOIDCUser(ctx, username, subject, role)
		if errors.Is(ierr, pg.ErrUserExists) {
			s.failOIDC(ctx, subject, "username_collision", username)
			s.sm.Put(ctx, "flash", "Sign-in failed: username already taken locally. Ask an admin to rename one side.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if ierr != nil {
			s.failOIDC(ctx, subject, "insert_failed", ierr.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		user = pg.User{ID: id, Username: username, Role: role}
		_ = subject // OIDCSubject value tracked in pg, unused on the cached struct
	case err != nil:
		s.failOIDC(ctx, subject, "lookup_failed", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	default:
		// Existing row — refresh role on claim-value change.
		if user.Role != role {
			if uerr := s.store.UpdateUserRole(ctx, user.ID, role); uerr != nil {
				// Stale role isn't a login blocker; log via audit and
				// continue with the cached role.
				s.failOIDC(ctx, subject, "role_update_failed", uerr.Error())
			} else {
				user.Role = role
			}
		}
	}

	if err := s.sm.RenewToken(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.sm.Put(ctx, sessionUserID, user.ID)
	s.sm.Put(ctx, sessionUsername, user.Username)
	s.sm.Put(ctx, sessionRole, string(user.Role))
	_ = s.store.LogAudit(ctx, pg.AuditEntry{
		ActorType: pg.ActorUser,
		ActorID:   user.ID,
		Action:    "auth.oidc.success",
		Detail: map[string]any{
			"subject":  subject,
			"username": user.Username,
			"role":     string(user.Role),
		},
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// failOIDC writes an auth.oidc.failure audit row. Best-effort.
func (s *Server) failOIDC(ctx context.Context, subject, reason, detail string) {
	s.telem.IncAuthnFailure()
	det := map[string]any{"reason": reason}
	if subject != "" {
		det["subject"] = subject
	}
	if detail != "" {
		det["detail"] = detail
	}
	_ = s.store.LogAudit(ctx, pg.AuditEntry{
		ActorType: pg.ActorUser,
		Action:    "auth.oidc.failure",
		Detail:    det,
	})
}

// mapOIDCRole walks the configured role claim's array values in the
// IdP's claims and returns the first matching role + true. Falls back
// to a string claim when the configured claim is a single string
// (some IdPs flatten single-value group memberships).
func mapOIDCRole(claims map[string]any, claimName string, mappings map[string]string) (pg.UserRole, bool) {
	if claimName == "" || len(mappings) == 0 {
		return "", false
	}
	raw, ok := claims[claimName]
	if !ok {
		return "", false
	}
	candidates := claimValueStrings(raw)
	for _, c := range candidates {
		if r, ok := mappings[c]; ok {
			return pg.UserRole(r), true
		}
	}
	return "", false
}

// claimValueStrings flattens a claim value into a string slice.
// Accepts string, []string, []any. Anything else returns nil.
func claimValueStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// stringClaim returns the string value of one ID-token claim, or "" if
// missing or non-string.
func stringClaim(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	v, ok := claims[name].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// randURLString returns n bytes of crypto-random data, base64url-
// encoded without padding.
func randURLString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge returns the S256 code-challenge for a verifier per
// RFC 7636 §4.2.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
