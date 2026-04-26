package console

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// Flash keys for the one-shot plaintext display after a mint.
const (
	flashTokenPlaintext = "token_plaintext"
	flashTokenHint      = "token_hint"
)

// defaultTokenTTL is the assumed TTL when the form is submitted
// without one. 1h matches the form default.
const defaultTokenTTL = time.Hour

// maxTokenTTL caps how long an enrolment token can sit unredeemed.
// 7d is enough for a slow rollout; longer windows should mint new
// tokens rather than holding one open.
const maxTokenTTL = 7 * 24 * time.Hour

func (s *Server) enrolmentTokensList(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListEnrollmentTokens(r.Context())
	if err != nil {
		http.Error(w, "list tokens failed", http.StatusInternalServerError)
		return
	}
	plain, _ := s.sm.Pop(r.Context(), flashTokenPlaintext).(string)
	hint, _ := s.sm.Pop(r.Context(), flashTokenHint).(string)
	render(w, r, views.EnrolmentTokens(views.EnrolmentTokensPageData{
		Tokens:         tokens,
		JustMinted:     plain,
		JustMintedHint: hint,
		DefaultServer:  s.defaultEnrollServer,
		Now:            time.Now().UTC(),
	}))
}

// enrolmentTokensCreate handles POST /enrolment-tokens. Generates a
// fresh random plaintext, hashes it, stores the row, and stashes the
// plaintext in scs flash so the redirect renders it once. Wrapped in
// RequireRole(admin) at registration. The pg-facing helpers retain
// "Enrollment" in their names because the underlying schema table is
// `enrollment_tokens` — schema migrations are append-only.
func (s *Server) enrolmentTokensCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	hint := strings.TrimSpace(r.PostFormValue("hostname_hint"))
	ttlStr := strings.TrimSpace(r.PostFormValue("ttl"))
	ttl := defaultTokenTTL
	if ttlStr != "" {
		parsed, err := time.ParseDuration(ttlStr)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid ttl — use Go duration syntax (e.g. 1h, 24h)", http.StatusBadRequest)
			return
		}
		if parsed > maxTokenTTL {
			http.Error(w, fmt.Sprintf("ttl above maximum %s", maxTokenTTL), http.StatusBadRequest)
			return
		}
		ttl = parsed
	}

	plaintext, err := mintTokenPlaintext()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := s.store.InsertEnrollmentToken(r.Context(),
		pg.HashEnrollmentToken(plaintext),
		s.userID(r),
		hint,
		time.Now().Add(ttl),
	); err != nil {
		http.Error(w, "store token failed", http.StatusInternalServerError)
		return
	}

	// Audit action string keeps the legacy "enrollment_token.create"
	// spelling so historical audit log queries don't break.
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType: pg.ActorUser,
		ActorID:   s.userID(r),
		Action:    "enrollment_token.create",
		Detail: map[string]any{
			"hostname_hint": hint,
			"ttl_seconds":   ttl.Seconds(),
		},
	})

	s.sm.Put(r.Context(), flashTokenPlaintext, plaintext)
	s.sm.Put(r.Context(), flashTokenHint, hint)
	http.Redirect(w, r, "/enrolment-tokens", http.StatusSeeOther)
}

func (s *Server) enrolmentTokensRevoke(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "token_id")
	if tokenID == "" {
		http.Error(w, "missing token_id", http.StatusBadRequest)
		return
	}
	switch err := s.store.RevokeEnrollmentToken(r.Context(), tokenID, s.userID(r)); {
	case errors.Is(err, pg.ErrTokenNotFound), errors.Is(err, pg.ErrTokenUsed):
		http.Error(w, "token not found or already used/revoked", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/enrolment-tokens", http.StatusSeeOther)
}

// mintTokenPlaintext returns 24 random bytes as URL-safe base64. The
// resulting 32-char string is wide enough to stop offline brute-force
// against the sha256 the database stores; URL-safe so it can ride a
// `--token=…` flag without quoting.
func mintTokenPlaintext() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
