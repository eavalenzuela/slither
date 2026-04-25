//go:build integration

// End-to-end test for the live-tail SSE handler. Real Postgres
// (testcontainers) for sessions + httptest server. Verifies:
//   - Two parallel SSE consumers both receive every published event.
//   - Closing one consumer (pause) does not stall the other or the bus.
//   - Filters narrow what each consumer sees without affecting peers.

package console_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/console"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestLiveTail_TwoConsumersBothReceive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupLiveEnv(ctx, t)
	defer env.cleanup()

	// Open two SSE connections from independent cookie jars (one
	// "browser tab" each).
	streamA := openLiveStream(t, env, "")
	defer streamA.close()
	streamB := openLiveStream(t, env, "")
	defer streamB.close()

	// Give the handlers a moment to run their goroutines + register
	// subscribers before the publish flood. Without this the bus may
	// fan out to zero subscribers.
	streamA.waitForDropsEvent(t, 2*time.Second)
	streamB.waitForDropsEvent(t, 2*time.Second)

	for i := 0; i < 5; i++ {
		env.bus.Publish(&pb.Envelope{
			EventId:    fmt.Sprintf("evt-%d", i),
			HostId:     "host-A",
			ClassId:    pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
			ObservedAt: timestamppb.Now(),
			Payload:    []byte(`{"hello":"world"}`),
		})
	}

	gotA := streamA.collectEvents(t, 5, 3*time.Second)
	gotB := streamB.collectEvents(t, 5, 3*time.Second)
	if len(gotA) != 5 || len(gotB) != 5 {
		t.Fatalf("event counts a=%d b=%d, want 5 each", len(gotA), len(gotB))
	}
	for _, ev := range gotA {
		if !strings.HasPrefix(ev.EventID, "evt-") || ev.HostID != "host-A" {
			t.Errorf("unexpected event payload: %+v", ev)
		}
	}
}

func TestLiveTail_PausedTabDoesNotStallPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupLiveEnv(ctx, t)
	defer env.cleanup()

	streamA := openLiveStream(t, env, "")
	streamB := openLiveStream(t, env, "")
	defer streamB.close()

	streamA.waitForDropsEvent(t, 2*time.Second)
	streamB.waitForDropsEvent(t, 2*time.Second)

	// Pause stream A by closing the connection. Stream B must still
	// receive new events.
	streamA.close()
	// Give the server's bus subscriber the moment it needs to detach.
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 3; i++ {
		env.bus.Publish(&pb.Envelope{
			EventId: fmt.Sprintf("post-pause-%d", i),
			HostId:  "host-A",
			ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
			Payload: []byte(`{}`),
		})
	}
	gotB := streamB.collectEvents(t, 3, 3*time.Second)
	if len(gotB) != 3 {
		t.Errorf("stream B post-pause events = %d, want 3", len(gotB))
	}
}

func TestLiveTail_ClassUIDFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupLiveEnv(ctx, t)
	defer env.cleanup()

	stream := openLiveStream(t, env, "class_uid=4001")
	defer stream.close()
	stream.waitForDropsEvent(t, 2*time.Second)

	// Publish a process-activity event (1007) that the filter should
	// drop, then a network event (4001) the filter should keep.
	env.bus.Publish(&pb.Envelope{
		EventId: "proc",
		ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		Payload: []byte(`{}`),
	})
	env.bus.Publish(&pb.Envelope{
		EventId: "net",
		ClassId: pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY,
		Payload: []byte(`{}`),
	})

	got := stream.collectEvents(t, 1, 2*time.Second)
	if len(got) != 1 || got[0].EventID != "net" {
		t.Errorf("filtered events = %+v, want one net event", got)
	}
}

// --- harness ---

type liveEnv struct {
	store   *pg.Store
	bus     *ingest.Bus
	ts      *httptest.Server
	cookie  *http.Cookie
	cleanup func()
}

func setupLiveEnv(ctx context.Context, t *testing.T) *liveEnv {
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
	if _, _, err := store.BootstrapAdmin(ctx, "admin", "horse"); err != nil {
		store.Close()
		stopPG()
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	key, _ := console.LoadOrCreateSessionKey("")
	bus := ingest.NewBus(nil)
	svc := console.New(console.Options{
		Store:      store,
		Telem:      telemetry.NewCounters(),
		Bus:        bus,
		SessionKey: key,
	})
	ts := httptest.NewServer(svc.Handler())

	// Log in once, capture the session cookie. SSE consumers reuse it.
	// Don't follow the redirect — Set-Cookie lands on the 302
	// response and http.Client's default redirect-follow loses it.
	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	form := url.Values{"username": {"admin"}, "password": {"horse"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp, err := noFollow.Do(req)
	if err != nil {
		ts.Close()
		store.Close()
		stopPG()
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()

	var cookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("no session cookie returned (status=%d): %+v", loginResp.StatusCode, loginResp.Cookies())
	}

	return &liveEnv{
		store:  store,
		bus:    bus,
		ts:     ts,
		cookie: cookie,
		cleanup: func() {
			ts.Close()
			bus.Close()
			store.Close()
			stopPG()
		},
	}
}

// --- SSE client ---

type sseStream struct {
	resp   *http.Response
	scan   *bufio.Scanner
	cancel context.CancelFunc
}

func openLiveStream(t *testing.T, env *liveEnv, query string) *sseStream {
	t.Helper()
	url := env.ts.URL + "/live/stream"
	if query != "" {
		url += "?" + query
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		t.Fatalf("new req: %v", err)
	}
	req.AddCookie(env.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("sse get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("sse status = %d", resp.StatusCode)
	}
	scan := bufio.NewScanner(resp.Body)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &sseStream{resp: resp, scan: scan, cancel: cancel}
}

func (s *sseStream) close() {
	s.cancel()
	if s.resp != nil && s.resp.Body != nil {
		_ = s.resp.Body.Close()
	}
}

// readFrame reads one SSE frame (event-type + data lines, terminated
// by a blank line). Returns "" / "" on stream end.
func (s *sseStream) readFrame() (eventType, data string, ok bool) {
	for s.scan.Scan() {
		line := s.scan.Text()
		if line == "" {
			if data != "" || eventType != "" {
				return eventType, data, true
			}
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		}
	}
	return "", "", false
}

// waitForDropsEvent reads frames until the initial "drops" frame
// arrives — proves the handler has subscribed. Tests publish events
// only after this signal so the subscription race is closed.
func (s *sseStream) waitForDropsEvent(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	doneC := make(chan bool, 1)
	go func() {
		for {
			eventType, _, ok := s.readFrame()
			if !ok {
				doneC <- false
				return
			}
			if eventType == "drops" {
				doneC <- true
				return
			}
		}
	}()
	select {
	case ok := <-doneC:
		if !ok {
			t.Fatal("stream closed before drops event")
		}
	case <-deadline:
		t.Fatal("timeout waiting for drops event")
	}
}

type liveEvent struct {
	EventID string `json:"event_id"`
	HostID  string `json:"host_id"`
	ClassID int32  `json:"class_id"`
}

// collectEvents reads frames until n default-typed events have been
// observed or the deadline expires. drops events are ignored.
func (s *sseStream) collectEvents(t *testing.T, n int, within time.Duration) []liveEvent {
	t.Helper()
	out := make([]liveEvent, 0, n)
	deadline := time.After(within)
	resultC := make(chan []liveEvent, 1)
	go func() {
		for len(out) < n {
			eventType, data, ok := s.readFrame()
			if !ok {
				resultC <- out
				return
			}
			if eventType != "" { // skip drops + comments
				continue
			}
			var ev liveEvent
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				continue
			}
			out = append(out, ev)
		}
		resultC <- out
	}()
	select {
	case got := <-resultC:
		return got
	case <-deadline:
		return out
	}
}
