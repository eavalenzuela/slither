//go:build integration

package pg

import (
	"context"
	"testing"
	"time"
)

func TestAuditChain_ResponseActionFullLifecycle(t *testing.T) {
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

	// Insert + walk pending → running → done. Each transition writes
	// an audit_log row inside the same tx as the state change.
	row, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID:  hostID,
		Action:  ResponseActionKillProcess,
		Target:  "1234",
		RuleUID: "audit-test",
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: row.ID, To: ResponseStatusRunning,
	}); err != nil {
		t.Fatalf("→running: %v", err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{
		ActionID: row.ID, To: ResponseStatusDone,
		Detail: "killed pid 1234 with SIGTERM",
	}); err != nil {
		t.Fatalf("→done: %v", err)
	}

	// ListAuditByTarget returns newest-first; expect 2 rows for
	// (pending→running, running→done). The Insert path itself does
	// NOT audit (the row is the artefact); only transitions do.
	got, err := s.ListAuditByTarget(ctx, "response_action", row.ID, 100)
	if err != nil {
		t.Fatalf("ListAuditByTarget: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("audit row count = %d, want 2; rows = %+v", len(got), got)
	}
	// Newest first: first entry is running→done, second is pending→running.
	if got[0].Action != "response.action.transition" {
		t.Errorf("audit[0].Action = %q, want response.action.transition", got[0].Action)
	}
	if next, ok := got[0].Detail["next_status"].(string); !ok || next != "done" {
		t.Errorf("audit[0].Detail.next_status = %v, want done", got[0].Detail["next_status"])
	}
	if next, ok := got[1].Detail["next_status"].(string); !ok || next != "running" {
		t.Errorf("audit[1].Detail.next_status = %v, want running", got[1].Detail["next_status"])
	}
}

func TestAuditChain_ReversalLinksForward(t *testing.T) {
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
		Target: hostID, RuleUID: "audit-rev-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: parent.ID, To: ResponseStatusRunning}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: parent.ID, To: ResponseStatusDone}); err != nil {
		t.Fatal(err)
	}

	reverse, err := s.InsertResponseAction(ctx, ResponseActionInsert{
		HostID: hostID, Action: ResponseActionUnisolateHost,
		Target: hostID, RuleUID: "audit-rev-test", ParentAction: parent.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: reverse.ID, To: ResponseStatusRunning}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TransitionResponseAction(ctx, ResponseActionTransition{ActionID: reverse.ID, To: ResponseStatusDone}); err != nil {
		t.Fatal(err)
	}

	// Parent's audit chain should now have a `response.action.reverted`
	// row in addition to the pending → running → done trail.
	parentAudit, err := s.ListAuditByTarget(ctx, "response_action", parent.ID, 100)
	if err != nil {
		t.Fatalf("ListAuditByTarget(parent): %v", err)
	}
	var sawReverted bool
	for _, a := range parentAudit {
		if a.Action == "response.action.reverted" {
			sawReverted = true
			if revertedBy, ok := a.Detail["reverted_by"].(string); !ok || revertedBy != reverse.ID {
				t.Errorf("reverted_by = %v, want %s", a.Detail["reverted_by"], reverse.ID)
			}
			break
		}
	}
	if !sawReverted {
		t.Fatalf("parent audit chain missing response.action.reverted entry; got = %+v", parentAudit)
	}
}

func TestAuditChain_HostPolicyUpsertAudits(t *testing.T) {
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
	if _, err := s.UpsertHostPolicy(ctx, HostPolicy{
		HostID: hostID, AllowKillProcess: true,
	}, ""); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := s.ListAuditByTarget(ctx, "host", hostID, 100)
	if err != nil {
		t.Fatalf("ListAuditByTarget: %v", err)
	}
	var sawPolicy bool
	for _, a := range got {
		if a.Action == "host.response_policy.upsert" {
			sawPolicy = true
			break
		}
	}
	if !sawPolicy {
		t.Fatalf("expected host.response_policy.upsert audit row; got = %+v", got)
	}
}
