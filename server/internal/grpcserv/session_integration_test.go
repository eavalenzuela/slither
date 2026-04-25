//go:build integration

// End-to-end test for AgentService.Session using a real Postgres
// (testcontainers-go) and an in-process gRPC server + client. Verifies:
//   - Authenticated session: events fan out via the bus, host_id stamped
//     from the trusted source, heartbeats bump hosts.last_seen.
//   - Unknown host_id → Unauthenticated, no events leak.
//   - Stream close decrements sessions_active.
//   - Auth failures bump the authn-failures counter.
//
// bufconn doesn't carry a TLS handshake, so the test injects
// SessionService.PeerHostIDExtractor instead of real client certs. The
// peer-cert path is exercised by mtls/sign_test.go and by the Enroll
// integration test; this file owns the post-handshake business logic.

package grpcserv_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/grpcserv"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestSession_AuthenticatedFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupSessionEnv(ctx, t, "host-flow")
	defer env.cleanup()

	stream, err := env.client.Session(ctx)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}

	// Send three events with deliberately-wrong host_ids; the handler
	// must stamp env.HostID before fan-out.
	for i := 0; i < 3; i++ {
		if err := stream.Send(&pb.ClientMessage{
			Kind: &pb.ClientMessage_Event{Event: &pb.Envelope{
				EventId: "evt", HostId: "wrong-id",
			}},
		}); err != nil {
			t.Fatalf("send event: %v", err)
		}
	}
	if err := stream.Send(&pb.ClientMessage{
		Kind: &pb.ClientMessage_Heartbeat{Heartbeat: &pb.Heartbeat{HostId: env.hostID}},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	deadline := time.After(5 * time.Second)
	got := 0
	for got < 3 {
		select {
		case ev := <-env.sub:
			if ev.GetHostId() != env.hostID {
				t.Errorf("envelope.HostId = %q, want %q (handler must stamp from peer)", ev.GetHostId(), env.hostID)
			}
			got++
		case <-deadline:
			t.Fatalf("only saw %d/3 events on bus", got)
		}
	}

	// Drain heartbeat — let the handler hit pg.UpdateHostLastSeen.
	for {
		snap := env.telem.Snapshot()
		if snap.Heartbeats >= 1 {
			break
		}
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("ctx done before heartbeat applied")
		}
	}

	// hosts.last_seen now non-null.
	var lastSeen *time.Time
	if err := env.store.Pool().QueryRow(ctx,
		"SELECT last_seen FROM hosts WHERE id = $1", env.hostID).Scan(&lastSeen); err != nil {
		t.Fatalf("select last_seen: %v", err)
	}
	if lastSeen == nil {
		t.Errorf("last_seen still NULL after heartbeat")
	}

	// Close the stream — sessions_active should drop back to 0.
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	deadline = time.After(2 * time.Second)
	for {
		snap := env.telem.Snapshot()
		if snap.SessionsActive == 0 && snap.SessionsClosed >= 1 {
			break
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			snap := env.telem.Snapshot()
			t.Fatalf("sessions_active=%d sessions_closed=%d after close", snap.SessionsActive, snap.SessionsClosed)
		}
	}
}

func TestSession_UnknownHostRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupSessionEnv(ctx, t, "host-bogus")
	defer env.cleanup()

	// Override the extractor on the next stream to return a host_id
	// that is NOT in hosts.
	env.svc.PeerHostIDExtractor = func(context.Context) (string, error) {
		return "00000000-0000-0000-0000-000000000000", nil
	}

	stream, err := env.client.Session(ctx)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	// Sending should produce an immediate stream-level error.
	_ = stream.Send(&pb.ClientMessage{
		Kind: &pb.ClientMessage_Event{Event: &pb.Envelope{EventId: "x"}},
	})
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected error on unauthenticated session")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
	if got := env.telem.Snapshot().AuthnFailures; got < 1 {
		t.Errorf("authn_failures = %d, want >=1", got)
	}
	// No event leaked onto the bus.
	select {
	case ev := <-env.sub:
		t.Errorf("event leaked from rejected session: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

// --- harness ---

type sessionEnv struct {
	store   *pg.Store
	bus     *ingest.Bus
	telem   *telemetry.Counters
	svc     *grpcserv.SessionService
	client  pb.AgentServiceClient
	sub     <-chan *pb.Envelope
	hostID  string
	cleanup func()
}

func setupSessionEnv(ctx context.Context, t *testing.T, hostnameHint string) *sessionEnv {
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

	// Seed a host directly so we don't need the full Enroll flow here.
	var hostID string
	if err := store.Pool().QueryRow(ctx, `
		INSERT INTO hosts (hostname, machine_id, os_name, os_version, kernel_version, arch, cert_serial)
		VALUES ($1, 'mid', 'debian', '13', '6.12', 'amd64', $1 || '-serial')
		RETURNING id::text
	`, hostnameHint).Scan(&hostID); err != nil {
		store.Close()
		stopPG()
		t.Fatalf("seed host: %v", err)
	}

	telem := telemetry.NewCounters()
	bus := ingest.NewBus(func(string) { telem.IncDropSubscriber() })
	sub := bus.Subscribe("test", 16)

	svc := grpcserv.NewSessionService(store, bus, telem)
	svc.PeerHostIDExtractor = func(context.Context) (string, error) { return hostID, nil }

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		store.Close()
		stopPG()
		t.Fatalf("grpc.NewClient: %v", err)
	}

	return &sessionEnv{
		store:  store,
		bus:    bus,
		telem:  telem,
		svc:    svc,
		client: pb.NewAgentServiceClient(conn),
		sub:    sub,
		hostID: hostID,
		cleanup: func() {
			_ = conn.Close()
			srv.Stop()
			bus.Close()
			store.Close()
			stopPG()
		},
	}
}

// silence unused-package warnings if a future refactor strips a path.
var _ = errors.Is
