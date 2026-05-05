// Phase 6 #120 — admin-only console pages for API-key lifecycle.
//
// Mirrors the enrolment-token UX (Phase 2 #45): mint via POST →
// the plaintext token surfaces in a one-shot scs flash so the
// operator can copy it; revoke via POST flips revoked_at = now().
// The list page never round-trips the plaintext.
//
// Audit: api_key.minted / api_key.revoked entries on every
// state-changing route. The middleware path stamps api_key.used
// per request via the JSON-API handlers (not here — keeps console
// audit lines distinct from JSON-API audit lines).

package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/t3rmit3/slither/server/internal/console/views"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func (s *Server) apiKeysList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListAPIKeys(r.Context(), 200)
	if err != nil {
		http.Error(w, "list api keys failed", http.StatusInternalServerError)
		return
	}
	flashRaw, _ := s.sm.Pop(r.Context(), "flash").(string)
	mintedRaw, _ := s.sm.Pop(r.Context(), "api_key_minted").(string)
	render(w, r, views.APIKeys(views.APIKeysData{
		Keys:        rows,
		Flash:       flashRaw,
		MintedToken: mintedRaw,
	}))
}

func (s *Server) apiKeysCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 200 {
		http.Error(w, "name required (≤200 chars)", http.StatusBadRequest)
		return
	}
	minted, err := s.store.InsertAPIKey(r.Context(), name, s.userID(r), nil)
	if err != nil {
		http.Error(w, "mint failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    s.userID(r),
		Action:     "api_key.minted",
		TargetKind: "api_key",
		TargetID:   minted.ID,
		Detail:     map[string]any{"name": name},
	})
	// One-shot flash with the plaintext token. The list page reads
	// it from `api_key_minted`, displays once, and the scs Pop
	// erases it for the next render.
	s.sm.Put(r.Context(), "api_key_minted", minted.Token)
	s.sm.Put(r.Context(), "flash", "API key minted. Copy it now — it won't be shown again.")
	http.Redirect(w, r, "/api/keys", http.StatusSeeOther)
}

func (s *Server) apiKeysRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	err := s.store.RevokeAPIKey(r.Context(), id)
	switch {
	case errors.Is(err, pg.ErrAPIKeyNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	_ = s.store.LogAudit(r.Context(), pg.AuditEntry{
		ActorType:  pg.ActorUser,
		ActorID:    s.userID(r),
		Action:     "api_key.revoked",
		TargetKind: "api_key",
		TargetID:   id,
	})
	s.sm.Put(r.Context(), "flash", "API key revoked.")
	http.Redirect(w, r, "/api/keys", http.StatusSeeOther)
}
