//go:build integration

package respond

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	pgcontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if sock := os.Getenv("DOCKER_HOST"); sock != "" {
		return
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skipf("respond integration: docker not reachable (%v); skipping", err)
	}
	c, derr := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
	if derr != nil {
		t.Skipf("respond integration: docker socket dial failed (%v); skipping", derr)
	}
	_ = c.Close()
}

func startPg(ctx context.Context, t *testing.T) (*pg.Store, func()) {
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
		t.Fatalf("pg start: %v", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("dsn: %v", err)
	}
	if err := pg.Migrate(ctx, dsn); err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("migrate: %v", err)
	}
	store, err := pg.Open(ctx, dsn)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("open: %v", err)
	}
	cleanup := func() {
		store.Close()
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(termCtx)
	}
	return store, cleanup
}

func seedHost(ctx context.Context, t *testing.T, s *pg.Store, hostname string) string {
	t.Helper()
	if _, err := s.Pool().Exec(ctx, `
		INSERT INTO hosts (
		    id, hostname, machine_id, os_name, os_version,
		    kernel_version, arch, cert_serial, enrolled_at
		) VALUES (gen_random_uuid(), $1, 'm', 'linux', '13', '6.12', 'amd64', '01', now())
	`, hostname); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	var id string
	if err := s.Pool().QueryRow(ctx,
		`SELECT id::text FROM hosts WHERE hostname = $1 LIMIT 1`, hostname,
	).Scan(&id); err != nil {
		t.Fatalf("read host id: %v", err)
	}
	return id
}

func TestHub_DispatchPolicyDenied(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, cleanup := startPg(ctx, t)
	defer cleanup()

	hostID := seedHost(ctx, t, store, "denied-host")

	h := NewHub(store, telemetry.NewCounters())
	row, err := h.Dispatch(ctx, DispatchInput{
		HostID:  hostID,
		Action:  pg.ResponseActionKillProcess,
		Target:  "1234",
		RuleUID: "test-rule",
	})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("Dispatch err = %v, want ErrPolicyDenied", err)
	}
	if row.Status != pg.ResponseStatusDeniedByPolicy {
		t.Fatalf("row.Status = %s, want denied_by_policy", row.Status)
	}
}

func TestHub_DispatchPermittedReachesSubscriber(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, cleanup := startPg(ctx, t)
	defer cleanup()

	hostID := seedHost(ctx, t, store, "permitted-host")
	if _, err := store.UpsertHostPolicy(ctx, pg.HostPolicy{
		HostID: hostID, AllowKillProcess: true,
	}, ""); err != nil {
		t.Fatalf("UpsertHostPolicy: %v", err)
	}

	h := NewHub(store, telemetry.NewCounters())
	ch, unsub := h.Subscribe(hostID)
	defer unsub()

	row, err := h.Dispatch(ctx, DispatchInput{
		HostID:  hostID,
		Action:  pg.ResponseActionKillProcess,
		Target:  "1234",
		RuleUID: "test-rule",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if row.Status != pg.ResponseStatusPending {
		t.Fatalf("row.Status = %s, want pending", row.Status)
	}

	select {
	case req := <-ch:
		if req.GetControlId() != row.ID {
			t.Errorf("control_id = %q, want %q", req.GetControlId(), row.ID)
		}
		if req.GetAction() != pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS {
			t.Errorf("action = %s, want KILL_PROCESS", req.GetAction())
		}
		if req.GetTarget() != "1234" {
			t.Errorf("target = %q, want 1234", req.GetTarget())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive ResponseRequest")
	}
}

func TestHub_OnResultTransitionsRow(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, cleanup := startPg(ctx, t)
	defer cleanup()

	hostID := seedHost(ctx, t, store, "result-host")
	if _, err := store.UpsertHostPolicy(ctx, pg.HostPolicy{
		HostID: hostID, AllowKillProcess: true,
	}, ""); err != nil {
		t.Fatalf("UpsertHostPolicy: %v", err)
	}

	h := NewHub(store, telemetry.NewCounters())
	_, unsub := h.Subscribe(hostID)
	defer unsub()

	row, err := h.Dispatch(ctx, DispatchInput{
		HostID:  hostID,
		Action:  pg.ResponseActionKillProcess,
		Target:  "999",
		RuleUID: "test-rule",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	if err := h.OnResult(ctx, &pb.ResponseResult{
		ControlId: row.ID,
		Status:    pb.ResponseStatus_RESPONSE_STATUS_DONE,
		Detail:    "killed pid 999",
	}); err != nil {
		t.Fatalf("OnResult: %v", err)
	}

	got, err := store.GetResponseAction(ctx, row.ID)
	if err != nil {
		t.Fatalf("GetResponseAction: %v", err)
	}
	if got.Status != pg.ResponseStatusDone {
		t.Fatalf("Status = %s, want done", got.Status)
	}
	if got.ReasonCode != "killed pid 999" {
		t.Errorf("ReasonCode = %q, want %q", got.ReasonCode, "killed pid 999")
	}
}
