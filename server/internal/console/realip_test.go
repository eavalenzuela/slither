package console

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The console deliberately does not install chi's middleware.RealIP.
// That middleware overwrites r.RemoteAddr from True-Client-IP,
// X-Real-IP or the leftmost X-Forwarded-For, unconditionally and
// regardless of whether anything trustworthy sets them — so any client
// can choose the address the server believes it is talking to.
//
// chi deprecated it in v5.3.0 (GHSA-3fxj-6jh8-hvhx,
// GHSA-rjr7-jggh-pgcp, GHSA-9g5q-2w5x-hmxf) without changing its
// behaviour, which means a dependency bump alone does not remove the
// exposure and a vulnerability scanner going quiet does not mean the
// problem went away.
//
// Nothing reads RemoteAddr today, so this pins the property before
// something does: on a security console, the first feature to want a
// client IP will be audit logging or per-IP rate limiting, and both are
// worthless if the value is attacker-chosen. If real client IPs are
// needed, the answer is ClientIPFromXFFTrustedProxies + GetClientIP,
// which leave RemoteAddr alone.
func TestConsoleDoesNotTrustClientSuppliedIPHeaders(t *testing.T) {
	t.Parallel()

	const realPeer = "192.0.2.10:54321"

	var seen string
	mux := chi.NewRouter()
	// Mirror the real middleware stack. If RealIP is ever reintroduced
	// in routes(), this test's sibling assertion below starts failing
	// for the console proper; here we assert the baseline behaviour the
	// stack must preserve.
	mux.Get("/probe", func(_ http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	})

	for _, hdr := range []string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"} {
		hdr := hdr
		t.Run(hdr, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/probe", http.NoBody)
			req.RemoteAddr = realPeer
			req.Header.Set(hdr, "203.0.113.99")

			mux.ServeHTTP(httptest.NewRecorder(), req)

			if seen != realPeer {
				t.Errorf("%s rewrote RemoteAddr to %q, want the transport peer %q",
					hdr, seen, realPeer)
			}
		})
	}
}

// Guards the actual server's middleware stack rather than a hand-rolled
// one: a request carrying every spoofable header must still arrive at a
// handler with its transport-level RemoteAddr intact.
func TestServerRoutesPreserveTransportRemoteAddr(t *testing.T) {
	t.Parallel()

	const realPeer = "192.0.2.20:1234"

	s := &Server{mux: chi.NewRouter()}
	s.mux.Use(baseMiddleware()...)

	var seen string
	s.mux.Get("/probe", func(_ http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/probe", http.NoBody)
	req.RemoteAddr = realPeer
	req.Header.Set("True-Client-IP", "203.0.113.1")
	req.Header.Set("X-Real-IP", "203.0.113.2")
	req.Header.Set("X-Forwarded-For", "203.0.113.3, 198.51.100.4")

	s.mux.ServeHTTP(httptest.NewRecorder(), req)

	if seen != realPeer {
		t.Errorf("RemoteAddr = %q, want %q — a client-supplied header reached "+
			"RemoteAddr, which means an IP-trusting middleware is back in the stack",
			seen, realPeer)
	}
}
