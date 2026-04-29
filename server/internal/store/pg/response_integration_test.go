//go:build integration

package pg

import (
	"context"
	"errors"
	"testing"
	"time"
)

// seedHostForResponse creates a hosts row that response_actions /
// host_response_policies can FK to. Returns the host id.
func seedHostForResponse(ctx context.Context, t *testing.T, s *Store) string {
	t.Helper()
	_, err := s.Pool().Exec(ctx, `
		INSERT INTO hosts (
		    id, hostname, machine_id, os_name, os_version,
		    kernel_version, arch, cert_serial, enrolled_at
		) VALUES (gen_random_uuid(), 'p4-host', 'm', 'linux', '13',
		          '6.12', 'amd64', '01', now())
	`)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	var hostID string
	if err := s.Pool().QueryRow(ctx,
		`SELECT id::text FROM hosts WHERE hostname = 'p4-host' LIMIT 1`,
	).Scan(&hostID); err != nil {
		t.Fatalf("read host id: %v", err)
	}
	return hostID
}

func TestResponseAction_InsertAndStateMachine(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hostID := seedHostForResponse(ctx, t, s)

	// Insert with rule_uid (edge auto-respond pattern).
	row, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID:  hostID,
		Action:  ResponseActionKillProcess,
		Target:  "1234",
		RuleUID: "rule-test",
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if row.Status != ResponseStatusPending {
		t.Errorf("status = %s, want pending", row.Status)
	}

	// pending -> running -> done is the happy path.
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: row.ID, To: ResponseStatusRunning,
	}); err != nil {
		t.Fatalf("transition to running: %v", err)
	}
	finished, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: row.ID, To: ResponseStatusDone,
		Detail: "killed pid 1234 with SIGTERM",
	})
	if err != nil {
		t.Fatalf("transition to done: %v", err)
	}
	if finished.Status != ResponseStatusDone {
		t.Errorf("status = %s, want done", finished.Status)
	}
	if finished.CompletedAt == nil {
		t.Error("completed_at should be set on done")
	}

	// Re-transitioning a terminal row to a non-revertible value must fail.
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: row.ID, To: ResponseStatusFailed,
	}); !errors.Is(err, ErrResponseInvalidTransition) {
		t.Errorf("done -> failed: err = %v, want ErrResponseInvalidTransition", err)
	}

	// Pending -> denied_by_policy is also legal (dispatcher rejection).
	denied, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID: hostID, Action: ResponseActionIsolateHost,
		Target: hostID, RuleUID: "rule-test",
	})
	if err != nil {
		t.Fatalf("Insert second: %v", err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: denied.ID, To: ResponseStatusDeniedByPolicy,
		Detail: "policy.allow_isolate=false",
	}); err != nil {
		t.Fatalf("transition denied: %v", err)
	}
}

func TestResponseAction_ReversalLinksParent(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hostID := seedHostForResponse(ctx, t, s)

	parent, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID: hostID, Action: ResponseActionIsolateHost,
		Target: hostID, RuleUID: "rule-iso",
	})
	if err != nil {
		t.Fatalf("Insert parent: %v", err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: parent.ID, To: ResponseStatusRunning}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: parent.ID, To: ResponseStatusDone}); err != nil {
		t.Fatal(err)
	}

	// Reversal: new row with parent_action set.
	reverse, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID: hostID, Action: ResponseActionUnisolateHost,
		Target: hostID, RuleUID: "rule-iso", ParentAction: parent.ID,
	})
	if err != nil {
		t.Fatalf("Insert reversal: %v", err)
	}
	if reverse.ParentAction != parent.ID {
		t.Errorf("reverse.ParentAction = %q, want %q", reverse.ParentAction, parent.ID)
	}

	// Drive the reversal to done — should flip the parent to reverted.
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: reverse.ID, To: ResponseStatusRunning}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: reverse.ID, To: ResponseStatusDone}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetResponseAction(ctx, parent.ID)
	if err != nil {
		t.Fatalf("GetResponseAction: %v", err)
	}
	if got.Status != ResponseStatusReverted {
		t.Errorf("parent.Status = %s, want reverted (auto-flipped on child Done)", got.Status)
	}
}

func TestResponseAction_RejectsAmbiguousActor(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	hostID := seedHostForResponse(ctx, t, s)
	if _, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID: hostID, Action: ResponseActionKillProcess, Target: "1",
		// Neither operator_id nor rule_uid set.
	}); err == nil {
		t.Fatal("expected insert without actor to fail")
	}
}

func TestHostPolicy_DefaultIsDetectOnly(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	hostID := seedHostForResponse(ctx, t, s)

	p, err := s.GetHostPolicy(ctx, hostID)
	if err != nil {
		t.Fatalf("GetHostPolicy: %v", err)
	}
	for _, allowed := range []bool{
		p.AllowKillProcess, p.AllowKillTree,
		p.AllowQuarantine, p.AllowIsolate, p.AllowCollect,
	} {
		if allowed {
			t.Errorf("default policy granted action: %+v", p)
			break
		}
	}
	if p.PermitsAction(ResponseActionKillProcess) {
		t.Error("PermitsAction(kill_process) on default policy should be false")
	}
}

func TestHostPolicy_UpsertAndUnisolateInheritance(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	hostID := seedHostForResponse(ctx, t, s)

	updated, err := s.UpsertHostPolicy(ctx, HostPolicy{
		HostID: hostID, AllowIsolate: true,
	}, "")
	if err != nil {
		t.Fatalf("UpsertHostPolicy: %v", err)
	}
	if !updated.AllowIsolate {
		t.Error("AllowIsolate not persisted")
	}
	// Unisolate inherits Isolate per ADR-0034.
	if !updated.PermitsAction(ResponseActionUnisolateHost) {
		t.Error("AllowIsolate=true should permit unisolate by inheritance")
	}
	if updated.PermitsAction(ResponseActionQuarantineFile) {
		t.Error("AllowIsolate should not imply allow_quarantine")
	}
}

func TestHostPolicy_NotifyFiresOnUpsert(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn, cleanup := startPostgres(ctx, t)
	defer cleanup()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	hostID := seedHostForResponse(ctx, t, s)

	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	notifications, err := s.WatchHostPolicies(watchCtx)
	if err != nil {
		t.Fatalf("WatchHostPolicies: %v", err)
	}

	if _, err := s.UpsertHostPolicy(ctx, HostPolicy{
		HostID: hostID, AllowCollect: true,
	}, ""); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	select {
	case <-notifications:
	case <-time.After(5 * time.Second):
		t.Fatal("no NOTIFY observed after policy upsert")
	}
}
