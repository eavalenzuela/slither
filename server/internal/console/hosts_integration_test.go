//go:build integration

// End-to-end tests for the host inventory page (#44). Real Postgres
// via testcontainers + httptest. Verifies:
//   - GET /hosts lists every enrolled host with status derivation.
//   - Viewer role does NOT see the Revoke button (no admin column).
//   - Admin POST /hosts/{id}/revoke flips revoked_at + audits.
//   - The previously-online host then fails the Session-stream
//     authn path because pg.HostExists treats revoked_at IS NOT NULL
//     as "not present".
//   - Revoke a non-existent host → 404.

package console_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/console"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestHosts_AdminListsAndRevokes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupHostsEnv(ctx, t, pg.RoleAdmin)
	defer env.cleanup()

	hostID := seedRevokableHost(ctx, t, env.store, "alpha")

	// List shows the host with a "unknown" status (never connected).
	body := getBody(t, env.ts, env.cookie, "/hosts")
	if !strings.Contains(body, hostID) {
		t.Errorf("hosts page missing host_id %s", hostID)
	}
	if !strings.Contains(body, "alpha") {
		t.Errorf("hosts page missing hostname")
	}
	if !strings.Contains(body, "unknown") {
		t.Errorf("expected status=unknown for never-connected host; body=%s", abbreviate(body))
	}
	// Admin sees the Revoke button.
	if !strings.Contains(body, ">Revoke<") {
		t.Errorf("admin should see Revoke button")
	}

	// Revoke.
	resp := postFormCookie(t, env.ts, env.cookie, "/hosts/"+hostID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", resp.StatusCode)
	}

	// HostExists now returns false → Session-stream authn would fail.
	exists, err := env.store.HostExists(ctx, hostID)
	if err != nil {
		t.Fatalf("HostExists: %v", err)
	}
	if exists {
		t.Error("revoked host still passes HostExists")
	}

	// Audit row written.
	var action, target string
	if err := env.store.Pool().QueryRow(ctx,
		`SELECT action, target_id::text FROM audit_log WHERE action='host.revoke' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&action, &target); err != nil {
		t.Fatalf("select audit: %v", err)
	}
	if action != "host.revoke" || target != hostID {
		t.Errorf("audit mismatch: action=%q target=%q", action, target)
	}

	// List now shows the host as "revoked".
	body = getBody(t, env.ts, env.cookie, "/hosts")
	if !strings.Contains(body, "revoked") {
		t.Errorf("hosts page should now show revoked badge")
	}

	// Re-revoke = 404.
	resp2 := postFormCookie(t, env.ts, env.cookie, "/hosts/"+hostID+"/revoke", url.Values{})
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("re-revoke status = %d, want 404", resp2.StatusCode)
	}
}

func TestHosts_ViewerDeniedRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupHostsEnv(ctx, t, pg.RoleViewer)
	defer env.cleanup()

	hostID := seedRevokableHost(ctx, t, env.store, "beta")

	// Viewer sees the list without the Revoke button.
	body := getBody(t, env.ts, env.cookie, "/hosts")
	if strings.Contains(body, ">Revoke<") {
		t.Error("viewer should not see Revoke button")
	}

	// Direct POST → 403.
	resp := postFormCookie(t, env.ts, env.cookie, "/hosts/"+hostID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer revoke status = %d, want 403", resp.StatusCode)
	}
}

// --- harness ---

type hostsEnv struct {
	store   *pg.Store
	ts      *httptest.Server
	cookie  *http.Cookie
	cleanup func()
}

func setupHostsEnv(ctx context.Context, t *testing.T, role pg.UserRole) *hostsEnv {
	t.Helper()
	requireDocker(t)

	dsn, stopPG := startPostgres(ctx, t)
	if err := pg.Migrate(ctx, dsn); err != nil {
		stopPG()
		t.Fatalf("Migrate: %v", err)
	}
	store, err := pg.Open(ctx, dsn)
	if err != nil {
		stopPG()
		t.Fatalf("pg.Open: %v", err)
	}

	const password = "horse-staple-test"
	username := "user-" + string(role)
	hash, err := pg.HashArgon2id(password)
	if err != nil {
		store.Close()
		stopPG()
		t.Fatalf("hash: %v", err)
	}
	if _, err := store.InsertUser(ctx, username, hash, role); err != nil {
		store.Close()
		stopPG()
		t.Fatalf("InsertUser: %v", err)
	}

	key, _ := console.LoadOrCreateSessionKey("")
	svc := console.New(ctx, console.Options{
		Store:      store,
		Telem:      telemetry.NewCounters(),
		SessionKey: key,
	})
	ts := httptest.NewServer(svc.Handler())

	cookie := loginCookie(t, ts, username, password)
	return &hostsEnv{
		store:  store,
		ts:     ts,
		cookie: cookie,
		cleanup: func() {
			ts.Close()
			store.Close()
			stopPG()
		},
	}
}

// seedRevokableHost inserts a host row directly so the test doesn't
// have to drive the full Enroll RPC. cert_serial uses hostname so
// the unique-index constraint isn't tripped between tests.
func seedRevokableHost(ctx context.Context, t *testing.T, store *pg.Store, hostname string) string {
	t.Helper()
	var id string
	if err := store.Pool().QueryRow(ctx, `
		INSERT INTO hosts (hostname, machine_id, os_name, os_version,
		                    kernel_version, arch, cert_serial)
		VALUES ($1, 'mid-'||$1, 'debian', '13', '6.12', 'amd64', $1 || '-serial')
		RETURNING id::text
	`, hostname).Scan(&id); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// --- httptest helpers (small + scoped to this file; the existing
// console_integration_test.go has its own helpers that rely on a
// global cookie jar shim, which doesn't compose cleanly when the
// per-test setup wants a fresh role + cookie pair) ---

func loginCookie(t *testing.T, ts *httptest.Server, username, password string) *http.Cookie {
	t.Helper()
	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	form := url.Values{"username": {username}, "password": {password}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	t.Fatalf("no session cookie (status=%d)", resp.StatusCode)
	return nil
}

func getBody(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func postFormCookie(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string, form url.Values) *http.Response {
	t.Helper()
	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func abbreviate(s string) string {
	if len(s) > 256 {
		return s[:256] + "…"
	}
	return s
}
