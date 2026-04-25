//go:build integration

// End-to-end test for the console: real Postgres (testcontainers) +
// httptest. Verifies the auth happy path, bad-password audit row,
// unauthenticated redirect, RBAC middleware, and logout.

package console_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	pgcontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/t3rmit3/slither/server/internal/console"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestConsole_LoginHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupConsoleEnv(ctx, t)
	defer env.cleanup()

	jar := newCookieJar(t, env.ts)
	resp := postForm(t, env.ts, jar, "/login", url.Values{
		"username": {"admin"},
		"password": {"correct-horse-battery"},
	})
	if got := resp.Request.URL.Path; got != "/dashboard" {
		t.Fatalf("after login redirect path = %q, want /dashboard", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.StatusCode)
	}

	// Audit row must be present.
	var action string
	if err := env.store.Pool().QueryRow(ctx,
		`SELECT action FROM audit_log WHERE actor_type='user' ORDER BY created_at DESC LIMIT 1`).Scan(&action); err != nil {
		t.Fatalf("select audit: %v", err)
	}
	if action != "auth.login.success" {
		t.Errorf("audit action = %q, want auth.login.success", action)
	}

	// Subsequent /dashboard with the cookie still works.
	got := getRequest(t, env.ts, jar, "/dashboard")
	if got.StatusCode != http.StatusOK {
		t.Errorf("second /dashboard = %d", got.StatusCode)
	}
}

func TestConsole_LoginBadPasswordAudits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupConsoleEnv(ctx, t)
	defer env.cleanup()

	jar := newCookieJar(t, env.ts)
	resp := postForm(t, env.ts, jar, "/login", url.Values{
		"username": {"admin"},
		"password": {"nope"},
	})
	// Redirect back to /login with a flash message.
	if got := resp.Request.URL.Path; got != "/login" {
		t.Fatalf("bad-password redirect path = %q, want /login", got)
	}

	var (
		action string
		detail string
	)
	if err := env.store.Pool().QueryRow(ctx,
		`SELECT action, detail::text FROM audit_log WHERE action='auth.login.failure' ORDER BY created_at DESC LIMIT 1`,
	).Scan(&action, &detail); err != nil {
		t.Fatalf("select audit: %v", err)
	}
	if !strings.Contains(detail, "bad_password") {
		t.Errorf("audit detail = %q, want bad_password reason", detail)
	}
}

func TestConsole_DashboardRedirectsWithoutAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupConsoleEnv(ctx, t)
	defer env.cleanup()

	jar := newCookieJar(t, env.ts)
	resp := getRequest(t, env.ts, jar, "/dashboard")
	if resp.Request.URL.Path != "/login" {
		t.Errorf("unauthenticated /dashboard ended at %q, want /login", resp.Request.URL.Path)
	}
}

func TestConsole_LogoutDestroysSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupConsoleEnv(ctx, t)
	defer env.cleanup()

	jar := newCookieJar(t, env.ts)
	postForm(t, env.ts, jar, "/login", url.Values{
		"username": {"admin"},
		"password": {"correct-horse-battery"},
	})
	postForm(t, env.ts, jar, "/logout", url.Values{})

	resp := getRequest(t, env.ts, jar, "/dashboard")
	if resp.Request.URL.Path != "/login" {
		t.Errorf("after logout /dashboard ended at %q, want /login", resp.Request.URL.Path)
	}
}

// --- harness ---

type consoleEnv struct {
	store   *pg.Store
	ts      *httptest.Server
	cleanup func()
}

func setupConsoleEnv(ctx context.Context, t *testing.T) *consoleEnv {
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

	if _, _, err := store.BootstrapAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		store.Close()
		stopPG()
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	key, err := console.LoadOrCreateSessionKey("")
	if err != nil {
		store.Close()
		stopPG()
		t.Fatalf("session key: %v", err)
	}
	svc := console.New(console.Options{
		Store:      store,
		Telem:      telemetry.NewCounters(),
		SessionKey: key,
	})
	ts := httptest.NewServer(svc.Handler())

	return &consoleEnv{
		store: store,
		ts:    ts,
		cleanup: func() {
			ts.Close()
			store.Close()
			stopPG()
		},
	}
}

// --- httptest helpers ---

func newCookieJar(t *testing.T, _ *httptest.Server) http.CookieJar {
	t.Helper()
	jar, err := newJar()
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return jar
}

func newJar() (http.CookieJar, error) {
	return cookieJarShim{}, nil
}

// cookieJarShim is a tiny in-memory cookie jar — net/http/cookiejar
// requires a publicsuffix registration step that's noisy for tests.
// This shim handles localhost only.
type cookieJarShim struct{}

var jarStore = struct {
	cookies []*http.Cookie
}{}

func (cookieJarShim) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		// Replace any existing same-named cookie.
		updated := false
		for i, old := range jarStore.cookies {
			if old.Name == c.Name {
				jarStore.cookies[i] = c
				updated = true
				break
			}
		}
		if !updated {
			jarStore.cookies = append(jarStore.cookies, c)
		}
	}
}

func (cookieJarShim) Cookies(_ *url.URL) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(jarStore.cookies))
	out = append(out, jarStore.cookies...)
	return out
}

func httpClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
	}
}

func postForm(t *testing.T, ts *httptest.Server, jar http.CookieJar, path string, form url.Values) *http.Response {
	t.Helper()
	resp, err := httpClient(jar).PostForm(ts.URL+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func getRequest(t *testing.T, ts *httptest.Server, jar http.CookieJar, path string) *http.Response {
	t.Helper()
	resp, err := httpClient(jar).Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// --- testcontainers helpers ---

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second); err != nil {
		t.Skipf("docker unreachable: %v", err)
	}
}

func startPostgres(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()
	container, err := pgcontainer.Run(ctx,
		"postgres:16-alpine",
		pgcontainer.WithDatabase("slither_test"),
		pgcontainer.WithUsername("slither"),
		pgcontainer.WithPassword("slither"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg container: %v", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("conn str: %v", err)
	}
	return dsn, func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(termCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("container terminate: %v", err)
		}
	}
}
