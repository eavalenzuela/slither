package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

type stubStore struct {
	row pg.APIKeyRow
	err error
}

func (s *stubStore) LookupAPIKey(_ context.Context, _ string) (pg.APIKeyRow, error) {
	return s.row, s.err
}

func makeReq(token string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/test", http.NoBody)
	if token != "" {
		r.Header.Set("Authorization", token)
	}
	return r
}

func TestMiddleware_MissingHeader(t *testing.T) {
	t.Parallel()
	mw := Middleware(&stubStore{err: errors.New("should not be called")})
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("downstream invoked despite missing auth")
	})).ServeHTTP(rr, makeReq(""))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "invalid_token" {
		t.Errorf("error = %q", body["error"])
	}
}

func TestMiddleware_BadScheme(t *testing.T) {
	t.Parallel()
	mw := Middleware(&stubStore{})
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).
		ServeHTTP(rr, makeReq("Basic Zm9vOmJhcg=="))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddleware_NotFound(t *testing.T) {
	t.Parallel()
	mw := Middleware(&stubStore{err: pg.ErrAPIKeyNotFound})
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("downstream invoked despite ErrAPIKeyNotFound")
	})).ServeHTTP(rr, makeReq("Bearer slither_apikey_x"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddleware_Revoked(t *testing.T) {
	t.Parallel()
	mw := Middleware(&stubStore{err: pg.ErrAPIKeyRevoked})
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("downstream invoked despite revoked key")
	})).ServeHTTP(rr, makeReq("Bearer slither_apikey_x"))
	// Revoked folds into the same 401 as ErrAPIKeyNotFound so token
	// holders can't probe whether a key was ever valid.
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddleware_Success(t *testing.T) {
	t.Parallel()
	row := pg.APIKeyRow{ID: "00000000-0000-4000-8000-000000000001", Name: "test"}
	mw := Middleware(&stubStore{row: row})
	called := false
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := APIKeyFrom(r.Context())
		if !ok {
			t.Error("APIKeyFrom returned !ok")
		}
		if got.ID != row.ID {
			t.Errorf("got.ID = %q, want %q", got.ID, row.ID)
		}
	})).ServeHTTP(rr, makeReq("Bearer slither_apikey_xyz"))
	if !called {
		t.Error("downstream not invoked on success")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestExtractBearer_TolerantOfCaseAndWhitespace(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hdr  string
		want string
		ok   bool
	}{
		{"empty", "", "", false},
		{"single", "Bearer", "", false},
		{"basic", "Basic abc", "", false},
		{"bearer-empty", "Bearer ", "", false},
		{"bearer-ok", "Bearer slither_apikey_xyz", "slither_apikey_xyz", true},
		{"lower-bearer", "bearer slither_apikey_xyz", "slither_apikey_xyz", true},
		{"trim", "Bearer  slither_apikey_xyz  ", "slither_apikey_xyz", true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", strings.NewReader(""))
			if c.hdr != "" {
				r.Header.Set("Authorization", c.hdr)
			}
			got, ok := extractBearer(r)
			if ok != c.ok || got != c.want {
				t.Errorf("got (%q,%v), want (%q,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}
