package grpc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// stubServer is a minimal AgentService implementation that:
//   - Accepts Session streams (multiple, one after another — the sink
//     reconnects after the server kills the prior stream).
//   - Collects every received event into a thread-safe slice so tests
//     can assert on it.
//   - Counts heartbeats.
//   - Exposes a killStream() that terminates the current stream from
//     the server side, which simulates a network blip.
type stubServer struct {
	pb.UnimplementedAgentServiceServer

	mu         sync.Mutex
	events     []*pb.Envelope
	heartbeats int

	killNext atomic.Bool
	killed   chan struct{}
}

func newStubServer() *stubServer {
	return &stubServer{killed: make(chan struct{}, 8)}
}

func (s *stubServer) Session(stream pb.AgentService_SessionServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if s.killNext.Load() {
			s.killNext.Store(false)
			select {
			case s.killed <- struct{}{}:
			default:
			}
			return io.EOF
		}
		switch k := msg.GetKind().(type) {
		case *pb.ClientMessage_Event:
			s.mu.Lock()
			s.events = append(s.events, k.Event)
			s.mu.Unlock()
		case *pb.ClientMessage_Heartbeat:
			s.mu.Lock()
			s.heartbeats++
			s.mu.Unlock()
		}
	}
}

func (s *stubServer) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *stubServer) heartbeatCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heartbeats
}

// spawnStubServer starts an in-process gRPC server on a bufconn listener.
// Returns the server + the dial option tests pass into the sink.
func spawnStubServer(t *testing.T) (*stubServer, []grpc.DialOption, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	stub := newStubServer()
	pb.RegisterAgentServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()

	dialOpts := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	return stub, dialOpts, func() {
		srv.Stop()
	}
}

func writeHostID(t *testing.T, id string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "host_id")
	if err := os.WriteFile(p, []byte(id+"\n"), 0o600); err != nil {
		t.Fatalf("write host_id: %v", err)
	}
	return p
}

// sampleEvent returns a minimal but valid OCSF ProcessActivity.
func sampleEvent(i int) ocsf.Event {
	return &ocsf.ProcessActivity{
		ClassUID: ocsf.ClassProcessActivity,
		Metadata: ocsf.Metadata{
			Version:   "1.3.0",
			UID:       "test-event-" + string(rune('a'+i)),
			OriginalT: time.Now().UnixMilli(),
		},
	}
}

func TestSink_StreamsEventsAndHeartbeats(t *testing.T) {
	stub, dialOpts, stop := spawnStubServer(t)
	defer stop()

	sink, err := New(Options{
		ServerAddr:        "passthrough:bufnet",
		HostIDPath:        writeHostID(t, "host-sink-01"),
		HeartbeatInterval: 100 * time.Millisecond,
		BufferSize:        16,
		AgentVersion:      "test",
		DialOptions:       dialOpts,
	}, telemetry.NewCounters())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan ocsf.Event, 8)
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx, in) }()

	// Push three events.
	for i := 0; i < 3; i++ {
		in <- sampleEvent(i)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stub.eventCount() >= 3 && stub.heartbeatCount() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := stub.eventCount(); got != 3 {
		t.Errorf("events received = %d, want 3", got)
	}
	if got := stub.heartbeatCount(); got < 1 {
		t.Errorf("heartbeats received = %d, want >=1", got)
	}
	// Validate envelope fields on the first event.
	stub.mu.Lock()
	env := stub.events[0]
	stub.mu.Unlock()
	if env.GetHostId() != "host-sink-01" {
		t.Errorf("envelope host_id = %q", env.GetHostId())
	}
	if env.GetClassId() != pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY {
		t.Errorf("envelope class_id = %v", env.GetClassId())
	}
	if len(env.GetPayload()) == 0 {
		t.Error("envelope payload empty")
	}
	// Round-trip the payload.
	var back ocsf.ProcessActivity
	if err := json.Unmarshal(env.GetPayload(), &back); err != nil {
		t.Errorf("payload json: %v", err)
	}
	if back.Metadata.UID == "" {
		t.Error("payload uid missing")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not stop after cancel")
	}
}

func TestSink_ReconnectsOnStreamKill(t *testing.T) {
	stub, dialOpts, stop := spawnStubServer(t)
	defer stop()

	telem := telemetry.NewCounters()
	sink, err := New(Options{
		ServerAddr:        "passthrough:bufnet",
		HostIDPath:        writeHostID(t, "host-reconnect"),
		HeartbeatInterval: time.Hour, // disable heartbeats here
		BufferSize:        16,
		DialOptions:       dialOpts,
	}, telem)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Speed up reconnect waits for the test: override jitter. We can't
	// mutate the constants; instead we rely on the default 1s initial
	// backoff and a generous test deadline.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan ocsf.Event, 32)
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx, in) }()

	// Event 1: flows through on stream 1.
	in <- sampleEvent(0)
	waitFor(t, func() bool { return stub.eventCount() >= 1 }, 3*time.Second, "first event")

	// Flip the kill-next flag. The next event will cause the server
	// to return EOF, closing the stream.
	stub.killNext.Store(true)
	in <- sampleEvent(1) // swallowed + stream closed
	<-stub.killed

	// Give the sink time to backoff + reconnect, then push another.
	// initialBackoff is 1s with ±25% jitter; 3s covers the worst case.
	time.Sleep(1500 * time.Millisecond)
	in <- sampleEvent(2)
	waitFor(t, func() bool { return stub.eventCount() >= 2 }, 3*time.Second, "post-reconnect event")

	if got := telem.Snapshot().OutputReconnects; got < 1 {
		t.Errorf("reconnect counter = %d, want >=1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not stop")
	}
}

func TestSink_DropOldestOnFull(t *testing.T) {
	// No server consumer — events pile up in the bounded buffer until
	// drop-oldest kicks in. We don't start a bufconn listener; instead
	// we point the sink at a non-dialable target with a short buffer
	// and flood it. Because grpc.NewClient is non-blocking, the sender
	// never drains the buffer and push() has to drop.
	telem := telemetry.NewCounters()
	// Dial an unroutable address so Session() never actually succeeds.
	sink, err := New(Options{
		ServerAddr:        "passthrough:nowhere",
		HostIDPath:        writeHostID(t, "host-drop"),
		HeartbeatInterval: time.Hour,
		BufferSize:        4,
		DialOptions: []grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				<-ctx.Done() // never return a conn
				return nil, ctx.Err()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
	}, telem)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan ocsf.Event, 64)
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx, in) }()

	// Pump 64 events through; buffer is 4, so ~60 drops.
	for i := 0; i < 64; i++ {
		in <- sampleEvent(i)
	}
	// Wait for ingest to consume them all.
	waitFor(t, func() bool { return len(in) == 0 }, 3*time.Second, "ingest drain")
	// Ingest is async from the push side; allow a beat for drop bookkeeping.
	time.Sleep(100 * time.Millisecond)

	if got := telem.Snapshot().DropsOutput; got == 0 {
		t.Errorf("expected nonzero DropsOutput; got 0")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not stop")
	}
}

func TestSink_RejectsEmptyHostIDFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host_id")
	if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{
		ServerAddr: "nope",
		HostIDPath: p,
	}, telemetry.NewCounters())
	if err == nil {
		t.Fatal("empty host_id file should have been rejected")
	}
}

func TestBackoffIncreases(t *testing.T) {
	cur := initialBackoff
	seen := []time.Duration{cur}
	for i := 0; i < 10; i++ {
		cur = nextBackoff(cur)
		seen = append(seen, cur)
	}
	if seen[len(seen)-1] != maxBackoff {
		t.Errorf("backoff never capped at maxBackoff; last=%v", seen[len(seen)-1])
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			t.Errorf("backoff decreased at step %d: %v -> %v", i, seen[i-1], seen[i])
		}
	}
}

func waitFor(t *testing.T, cond func() bool, within time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", label)
}
