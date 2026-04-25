//go:build integration

// End-to-end test for #39 rule distribution over Session. Real Postgres
// (testcontainers) drives LISTEN/NOTIFY; an in-process gRPC server runs
// SessionService on a bufconn listener with PeerHostIDExtractor stubbed
// (mTLS is exercised by mtls/sign_test.go and the Enroll integration
// test). Verifies:
//   - Initial RuleSet on Subscribe.
//   - Insert into pg.rules → connected session sees the new rule
//     within the runner's debounce + fallback budget.
//   - SetRuleEnabled(false) → rule disappears from the next RuleSet.
//   - Two concurrent sessions both receive every update.

package grpcserv_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/control"
	"github.com/t3rmit3/slither/server/internal/grpcserv"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

const ruleSampleYAML = `title: Push test rule
id: 22222222-2222-4222-8222-222222222222
description: e2e
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /bin/bash
  condition: selection
`

func TestRulePush_InitialAndInsertAndDisable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupRulePushEnv(ctx, t)
	defer env.cleanup()

	stream, err := env.client.Session(ctx)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}

	// Initial RuleSet — the seeded rule was inserted before the runner
	// did its first Refresh, so it should be present right away.
	rs := mustRecvRuleSet(t, stream, 5*time.Second)
	if len(rs.GetRules()) != 1 || rs.GetRules()[0].GetRuleId() != "seed-rule" {
		t.Fatalf("initial ruleset rules = %+v", rs.GetRules())
	}

	// Insert a new rule. Trigger NOTIFY → debounce → Refresh → push.
	if err := env.store.InsertRule(ctx, "rule-x", "X", ruleSampleYAML, ""); err != nil {
		t.Fatalf("InsertRule: %v", err)
	}
	rs = waitForRuleSetWith(t, stream, "rule-x", 3*time.Second)
	if rs == nil {
		t.Fatal("did not receive ruleset containing rule-x")
	}

	// Disable the seed rule. The next push should omit it.
	if err := env.store.SetRuleEnabled(ctx, "seed-rule", false); err != nil {
		t.Fatalf("SetRuleEnabled: %v", err)
	}
	rs = waitForRuleSetWithout(t, stream, "seed-rule", 3*time.Second)
	if rs == nil {
		t.Fatal("did not receive ruleset that excludes the disabled rule")
	}

	if got := env.telem.Snapshot().RulesetsPushed; got < 1 {
		t.Errorf("rulesets_pushed = %d, want >= 1", got)
	}
}

func TestRulePush_TwoConcurrentSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupRulePushEnv(ctx, t)
	defer env.cleanup()

	// Use a counter-based extractor so the first Session resolves to
	// host A and the second to host B without mutating shared state
	// from the test goroutine after streams open (avoids data races
	// between the test's write and the server handler's read).
	var seq int32
	env.svc.PeerHostIDExtractor = func(context.Context) (string, error) {
		n := atomic.AddInt32(&seq, 1)
		if n == 1 {
			return env.hostA, nil
		}
		return env.hostB, nil
	}
	streamA, err := env.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	streamB, err := env.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Both consume the initial seed.
	mustRecvRuleSet(t, streamA, 5*time.Second)
	mustRecvRuleSet(t, streamB, 5*time.Second)

	if err := env.store.InsertRule(ctx, "shared-rule", "S", ruleSampleYAML, ""); err != nil {
		t.Fatal(err)
	}
	if waitForRuleSetWith(t, streamA, "shared-rule", 3*time.Second) == nil {
		t.Error("session A missed shared-rule")
	}
	if waitForRuleSetWith(t, streamB, "shared-rule", 3*time.Second) == nil {
		t.Error("session B missed shared-rule")
	}
}

// --- harness ---

type rulePushEnv struct {
	store   *pg.Store
	hub     *control.Hub
	telem   *telemetry.Counters
	svc     *grpcserv.SessionService
	client  pb.AgentServiceClient
	hostA   string
	hostB   string
	cleanup func()
}

func setupRulePushEnv(ctx context.Context, t *testing.T) *rulePushEnv {
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

	// Seed an admin user + two host rows so HostExists passes for both
	// concurrent-session host_ids.
	uid, err := store.InsertUser(ctx, "admin", "$argon2id$placeholder", pg.RoleAdmin)
	if err != nil {
		store.Close()
		stopPG()
		t.Fatalf("InsertUser: %v", err)
	}
	hostA := seedHost(ctx, t, store, "rules-A")
	hostB := seedHost(ctx, t, store, "rules-B")

	if err := store.InsertRule(ctx, "seed-rule", "Seed", ruleSampleYAML, uid); err != nil {
		store.Close()
		stopPG()
		t.Fatalf("seed rule: %v", err)
	}

	telem := telemetry.NewCounters()
	hub := control.NewHub(store, telem)
	bus := ingest.NewBus(nil)

	// Run the control runner; tighten debounce so the test asserts
	// convergence under a couple of seconds.
	runnerCtx, runnerCancel := context.WithCancel(ctx)
	go func() {
		_ = control.Run(runnerCtx, hub, store, control.RunnerOptions{
			Debounce:     50 * time.Millisecond,
			FallbackPoll: 5 * time.Second,
		})
	}()
	// Wait for the initial Refresh to land before any test starts —
	// otherwise the streamA happy-path race with the runner.
	deadline := time.Now().Add(5 * time.Second)
	for hub.Current() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	svc := grpcserv.NewSessionService(store, bus, telem)
	svc.RuleHub = hub
	svc.PeerHostIDExtractor = func(context.Context) (string, error) { return hostA, nil }

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
		runnerCancel()
		srv.Stop()
		store.Close()
		stopPG()
		t.Fatalf("grpc.NewClient: %v", err)
	}

	return &rulePushEnv{
		store:  store,
		hub:    hub,
		telem:  telem,
		svc:    svc,
		client: pb.NewAgentServiceClient(conn),
		hostA:  hostA,
		hostB:  hostB,
		cleanup: func() {
			runnerCancel()
			_ = conn.Close()
			srv.Stop()
			bus.Close()
			store.Close()
			stopPG()
		},
	}
}

func seedHost(ctx context.Context, t *testing.T, store *pg.Store, hint string) string {
	t.Helper()
	var id string
	if err := store.Pool().QueryRow(ctx, `
		INSERT INTO hosts (hostname, machine_id, os_name, os_version, kernel_version, arch, cert_serial)
		VALUES ($1, 'mid-'||$1, 'debian', '13', '6.12', 'amd64', $1 || '-serial')
		RETURNING id::text
	`, hint).Scan(&id); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func mustRecvRuleSet(t *testing.T, stream pb.AgentService_SessionClient, within time.Duration) *pb.RuleSet {
	t.Helper()
	type res struct {
		msg *pb.ServerMessage
		err error
	}
	c := make(chan res, 1)
	go func() {
		msg, err := stream.Recv()
		c <- res{msg, err}
	}()
	select {
	case r := <-c:
		if r.err != nil {
			t.Fatalf("Recv: %v", r.err)
		}
		k, ok := r.msg.GetKind().(*pb.ServerMessage_RuleSet)
		if !ok {
			t.Fatalf("expected RuleSet kind; got %T", r.msg.GetKind())
		}
		return k.RuleSet
	case <-time.After(within):
		t.Fatalf("timeout waiting for ruleset")
		return nil
	}
}

func waitForRuleSetWith(t *testing.T, stream pb.AgentService_SessionClient, ruleID string, within time.Duration) *pb.RuleSet {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		rs := mustRecvRuleSet(t, stream, within)
		for _, r := range rs.GetRules() {
			if r.GetRuleId() == ruleID {
				return rs
			}
		}
	}
	return nil
}

func waitForRuleSetWithout(t *testing.T, stream pb.AgentService_SessionClient, ruleID string, within time.Duration) *pb.RuleSet {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		rs := mustRecvRuleSet(t, stream, within)
		found := false
		for _, r := range rs.GetRules() {
			if r.GetRuleId() == ruleID {
				found = true
				break
			}
		}
		if !found {
			return rs
		}
	}
	return nil
}
