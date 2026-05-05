package v1

import (
	"encoding/json"
	"io"
	"net/http"
)

// errBody is the canonical JSON-error shape every handler emits on
// a 4xx/5xx. Mirrors the apiauth middleware's wire shape so a
// consumer parsing the body finds the same {error, message} pair
// regardless of which layer rejected the request.
type errBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeError emits a canonical JSON error body + the matching status.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: code, Message: message})
}

// jsonEncode wraps json.NewEncoder so callers can swap encoders
// (e.g. for golden tests) without re-importing encoding/json.
func jsonEncode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
