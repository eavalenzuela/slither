// Phase 6 #120 — bearer-token middleware for the read-only JSON API.
//
// Mounted on /api/v1/* only; the HTML console's /login + scs cookie
// path is untouched. The middleware:
//
//   1. Extracts the Authorization: Bearer <token> header.
//   2. Calls pg.Store.LookupAPIKey to verify the token (prefix-index
//      lookup + argon2id compare on the candidate row).
//   3. On success, stamps the resolved api-key id into the request
//      context so handlers can audit-log key.used events.
//   4. On failure, returns a JSON 401/403 — never the HTML login
//      page. Keeps the API surface free of HTML so consumers parsing
//      JSON never have to special-case auth-failure HTML.
//
// Failure mapping:
//   - missing/malformed header → 401 invalid_token
//   - lookup says ErrAPIKeyNotFound → 401 invalid_token
//   - lookup says ErrAPIKeyRevoked → 401 invalid_token (not 403 —
//     leaking the distinction lets a holder probe to confirm a
//     stolen-then-revoked token was once valid)
//   - DB error → 500 internal
//
// audit.api_key.used fires on success once per request via the
// caller's standard pg.LogAudit pathway. The middleware doesn't log
// directly to keep the dependency surface narrow — handlers wire
// audit calls inline so the per-route action ("api.events.search",
// etc.) is correctly attributed.

package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// ContextKey is the type used for context-value lookups so collisions
// with other packages stamping the same context can't happen.
type contextKey string

const (
	// ctxKeyAPIKey carries the verified APIKeyRow into the handler
	// chain. Handlers extract via APIKeyFrom(ctx).
	ctxKeyAPIKey contextKey = "api_key"
)

// Store is the narrow pg surface the middleware needs. *pg.Store
// satisfies it; tests pass an in-memory stub.
type Store interface {
	LookupAPIKey(ctx context.Context, token string) (pg.APIKeyRow, error)
}

// APIKeyFrom returns the verified APIKeyRow stamped into the
// request context. Returns the zero value + false when the request
// went through an unauthenticated route.
func APIKeyFrom(ctx context.Context) (pg.APIKeyRow, bool) {
	v, ok := ctx.Value(ctxKeyAPIKey).(pg.APIKeyRow)
	return v, ok
}

// Middleware returns a chi-compatible middleware that authenticates
// every request via the Authorization: Bearer <token> header.
func Middleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := extractBearer(r)
			if !ok {
				writeJSONError(w, http.StatusUnauthorized,
					"invalid_token", "missing or malformed Authorization header")
				return
			}
			row, err := store.LookupAPIKey(r.Context(), tok)
			switch {
			case errors.Is(err, pg.ErrAPIKeyNotFound),
				errors.Is(err, pg.ErrAPIKeyRevoked):
				// Both fold to the same 401 so revoked-token holders
				// can't probe whether the key was ever valid.
				writeJSONError(w, http.StatusUnauthorized,
					"invalid_token", "token rejected")
				return
			case err != nil:
				writeJSONError(w, http.StatusInternalServerError,
					"internal_error", "auth lookup failed")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyAPIKey, row)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer pulls the bearer token out of the Authorization
// header. Tolerates either "Bearer <token>" or "bearer <token>";
// rejects empty or non-Bearer schemes so an operator who tunnels
// a basic-auth header through the JSON-API gate sees a clear
// 401 rather than a silent reject.
func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// writeJSONError emits the canonical {error, message} body the JSON
// API uses for every 4xx/5xx. Mirrors the eyeexam contract so a
// consumer parsing the body finds the same shape on every failure.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := map[string]string{
		"error":   code,
		"message": message,
	}
	_ = json.NewEncoder(w).Encode(body)
}
