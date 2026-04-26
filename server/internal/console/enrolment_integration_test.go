//go:build integration

// End-to-end tests for #45 enrollment-token UX. Verifies:
//   - Admin POST /enrolment-tokens mints a row + flashes the
//     plaintext exactly once on the next render.
//   - Subsequent /enrolment-tokens GET no longer shows the plaintext.
//   - Revoke flips used_at; the Enroll RPC's ClaimEnrollmentToken
//     then errors with ErrTokenUsed for that token.
//   - Viewer denied on POST mint + revoke.
//   - Bad TTL (negative, > 7d, malformed) → 400.

package console_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func TestEnrolmentTokens_AdminMintRevokeFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupHostsEnv(ctx, t, pg.RoleAdmin)
	defer env.cleanup()

	// Mint via the admin form.
	resp := postFormCookie(t, env.ts, env.cookie, "/enrolment-tokens", url.Values{
		"hostname_hint": {"agent-mint-1"},
		"ttl":           {"2h"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("mint status = %d, want 303", resp.StatusCode)
	}

	// First GET after mint shows the plaintext block.
	body := getBody(t, env.ts, env.cookie, "/enrolment-tokens")
	if !strings.Contains(body, "copy now, it will not be shown again") {
		t.Errorf("flash banner missing on first render after mint")
	}
	// Extract the plaintext from the rendered <pre class="event-summary">…</pre>.
	plaintext := extractTokenPlaintext(t, body)
	if plaintext == "" {
		t.Fatal("could not parse token plaintext from page")
	}

	// Second GET — flash already popped.
	body2 := getBody(t, env.ts, env.cookie, "/enrolment-tokens")
	if strings.Contains(body2, plaintext) {
		t.Errorf("plaintext leaked on second render — flash should have been one-shot")
	}
	if !strings.Contains(body2, "agent-mint-1") {
		t.Errorf("hostname_hint missing from list view")
	}
	if !strings.Contains(body2, ">active<") {
		t.Errorf("freshly-minted token should render as active")
	}

	// Token round-trips through the Enroll RPC's hash check.
	if _, err := env.store.ClaimEnrollmentToken(ctx,
		pg.HashEnrollmentToken(plaintext),
		pg.HostFingerprint{
			Hostname: "agent-mint-1", MachineID: "mid", OSName: "debian",
			OSVersion: "13", KernelVersion: "6.12", Arch: "amd64",
		}, "serial-mint-1"); err != nil {
		t.Errorf("ClaimEnrollmentToken with minted plaintext: %v", err)
	}

	// Mint another token, then revoke it before any agent claims it.
	resp = postFormCookie(t, env.ts, env.cookie, "/enrolment-tokens", url.Values{
		"hostname_hint": {"agent-revoke-1"},
		"ttl":           {"1h"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("second mint status = %d", resp.StatusCode)
	}
	body3 := getBody(t, env.ts, env.cookie, "/enrolment-tokens")
	plaintext2 := extractTokenPlaintext(t, body3)
	if plaintext2 == "" {
		t.Fatal("second mint plaintext missing")
	}

	tokenID := getActiveTokenID(ctx, t, env.store, "agent-revoke-1")
	resp = postFormCookie(t, env.ts, env.cookie,
		"/enrolment-tokens/"+tokenID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", resp.StatusCode)
	}

	// Enroll RPC now refuses the revoked token.
	_, err := env.store.ClaimEnrollmentToken(ctx,
		pg.HashEnrollmentToken(plaintext2),
		pg.HostFingerprint{Hostname: "x", MachineID: "x", OSName: "x", OSVersion: "x", KernelVersion: "x", Arch: "x"},
		"serial-revoke-1")
	if err != pg.ErrTokenUsed {
		t.Errorf("post-revoke claim err = %v, want ErrTokenUsed", err)
	}

	// Re-revoke = 404 (mapped from "not found OR already used").
	resp = postFormCookie(t, env.ts, env.cookie,
		"/enrolment-tokens/"+tokenID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("re-revoke status = %d, want 404", resp.StatusCode)
	}
}

func TestEnrolmentTokens_ViewerDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupHostsEnv(ctx, t, pg.RoleViewer)
	defer env.cleanup()

	// Even the GET is admin-only — viewers shouldn't see the page.
	body := getBody(t, env.ts, env.cookie, "/enrolment-tokens")
	if strings.Contains(body, "Mint enrolment token") {
		t.Errorf("viewer should not see the mint form")
	}

	resp := postFormCookie(t, env.ts, env.cookie, "/enrolment-tokens", url.Values{
		"hostname_hint": {"x"}, "ttl": {"1h"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer mint status = %d, want 403", resp.StatusCode)
	}

	// Direct revoke also 403s.
	resp = postFormCookie(t, env.ts, env.cookie,
		"/enrolment-tokens/00000000-0000-0000-0000-000000000000/revoke", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer revoke status = %d, want 403", resp.StatusCode)
	}
}

func TestEnrolmentTokens_BadTTLRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupHostsEnv(ctx, t, pg.RoleAdmin)
	defer env.cleanup()

	cases := map[string]string{
		"empty-malformed": "not-a-duration",
		"negative":        "-1h",
		"too-long":        "30d", // Go duration parser rejects "d"; double cover
		"way-too-long":    "168h1m",
	}
	for name, ttl := range cases {
		t.Run(name, func(t *testing.T) {
			resp := postFormCookie(t, env.ts, env.cookie, "/enrolment-tokens", url.Values{
				"ttl": {ttl},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("ttl=%q status = %d, want 400", ttl, resp.StatusCode)
			}
		})
	}
}

// extractTokenPlaintext finds the plaintext token printed inside the
// flash card. The card uses <pre class="event-summary">PLAINTEXT</pre>
// on a line of its own — quick string-cut is enough for tests.
func extractTokenPlaintext(t *testing.T, body string) string {
	t.Helper()
	const startMarker = `<pre class="event-summary">`
	i := strings.Index(body, startMarker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(startMarker):]
	end := strings.Index(rest, "</pre>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

// getActiveTokenID looks up the most recent active token bearing the
// given hostname_hint. Avoids depending on the table's UUID being
// rendered into the HTML.
func getActiveTokenID(ctx context.Context, t *testing.T, store *pg.Store, hint string) string {
	t.Helper()
	var id string
	if err := store.Pool().QueryRow(ctx, `
		SELECT id::text FROM enrollment_tokens
		WHERE hostname_hint = $1 AND used_at IS NULL
		ORDER BY created_at DESC LIMIT 1
	`, hint).Scan(&id); err != nil {
		t.Fatalf("look up token id by hint %q: %v", hint, err)
	}
	return id
}
