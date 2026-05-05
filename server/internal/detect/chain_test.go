package detect

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// stubChainStore implements ChainStore + ChainCHStore for the verifier
// tests. Records every call so assertions can inspect ordering +
// content without an integration testcontainer.
type stubChainStore struct {
	respCount    uint64
	findingCount uint64
	respErr      error
	chErr        error

	recorded   pg.ChainSummaryInsert
	recordedID string
	recordErr  error

	auditEntries []pg.AuditEntry
}

func (s *stubChainStore) CountResponseActionsForChain(_ context.Context, _ string, _, _ time.Time) (uint64, error) {
	if s.respErr != nil {
		return 0, s.respErr
	}
	return s.respCount, nil
}

func (s *stubChainStore) RecordChainSummary(_ context.Context, in pg.ChainSummaryInsert) (string, error) {
	if s.recordErr != nil {
		return "", s.recordErr
	}
	s.recorded = in
	s.recordedID = "row-" + in.HostID
	return s.recordedID, nil
}

func (s *stubChainStore) LogAudit(_ context.Context, e pg.AuditEntry) error {
	s.auditEntries = append(s.auditEntries, e)
	return nil
}

func (s *stubChainStore) CountDetectionFindingsForChain(_ context.Context, _ string, _, _ time.Time) (uint64, error) {
	if s.chErr != nil {
		return 0, s.chErr
	}
	return s.findingCount, nil
}

func mkSummary(count uint64, since, until time.Time) *pb.ChainSummary {
	return &pb.ChainSummary{
		LastSeq:    42,
		LastHash:   "deadbeef",
		Count:      count,
		Since:      timestamppb.New(since),
		ObservedAt: timestamppb.New(until),
	}
}

// 9 = 3 response_actions + 6 findings; agent reports 9 → no mismatch.
func TestChainVerifier_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 3, findingCount: 6}
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	if err := v.Verify(context.Background(), "00000000-0000-4000-8000-000000000001", mkSummary(9, since, until)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if stub.recorded.Mismatch {
		t.Error("recorded mismatch=true on equal counts")
	}
	if stub.recorded.CountObserved != 9 || stub.recorded.CountExpected != 9 {
		t.Errorf("counts = (%d,%d), want (9,9)", stub.recorded.CountObserved, stub.recorded.CountExpected)
	}
	if len(stub.auditEntries) != 0 {
		t.Errorf("audit fired on happy path: %+v", stub.auditEntries)
	}
}

// SkewSlack=1 swallows a single-row delta — no mismatch.
func TestChainVerifier_SkewSlackAbsorbs(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 3, findingCount: 6} // expected = 9
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	// agent reports 8 — 1 short. Default skew slack (1) absorbs it.
	if err := v.Verify(context.Background(), "00000000-0000-4000-8000-000000000002", mkSummary(8, since, until)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if stub.recorded.Mismatch {
		t.Error("mismatch=true within skew slack")
	}
	if len(stub.auditEntries) != 0 {
		t.Error("audit fired within skew slack")
	}
}

// Beyond skew → mismatch, audit row, severity 4.
func TestChainVerifier_MismatchFiresAudit(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 3, findingCount: 6} // expected = 9
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	// agent reports 4 — 5 short, beyond default slack of 1.
	hostID := "00000000-0000-4000-8000-000000000003"
	if err := v.Verify(context.Background(), hostID, mkSummary(4, since, until)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !stub.recorded.Mismatch {
		t.Error("mismatch=false on a 5-row delta")
	}
	if len(stub.auditEntries) != 1 {
		t.Fatalf("audit count = %d, want 1", len(stub.auditEntries))
	}
	a := stub.auditEntries[0]
	if a.Action != "chain.mismatch" {
		t.Errorf("audit action = %q, want chain.mismatch", a.Action)
	}
	if a.ActorType != pg.ActorAgent {
		t.Errorf("audit actor_type = %q, want agent", a.ActorType)
	}
	if a.ActorID != hostID {
		t.Errorf("audit actor_id = %q, want %q", a.ActorID, hostID)
	}
	if sev, ok := a.Detail["severity"].(int); !ok || sev != 4 {
		t.Errorf("audit severity = %v, want 4", a.Detail["severity"])
	}
}

// CH down → degrades to pg-only count; mismatch path still works.
func TestChainVerifier_CHErrorDegrades(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 3, chErr: errors.New("ch down")}
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	// agent reports 9; pg-only expected = 3 → mismatch.
	if err := v.Verify(context.Background(), "00000000-0000-4000-8000-000000000004", mkSummary(9, since, until)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if stub.recorded.CountExpected != 3 {
		t.Errorf("expected = %d, want 3 (CH down → pg-only)", stub.recorded.CountExpected)
	}
	if !stub.recorded.Mismatch {
		t.Error("mismatch=false despite 6-row delta after CH-down degrade")
	}
	if len(stub.auditEntries) != 1 {
		t.Errorf("audit count = %d, want 1", len(stub.auditEntries))
	}
	if pres, ok := stub.auditEntries[0].Detail["ch_count_present"].(bool); !ok || pres {
		t.Errorf("ch_count_present detail = %v, want false", stub.auditEntries[0].Detail["ch_count_present"])
	}
}

// Inverted window (since >= observed_at) records the row but skips
// the count divergence check — used on the agent's first tick.
func TestChainVerifier_InvertedWindowSkipsCount(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 99, findingCount: 99}
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	now := time.Now().UTC()
	if err := v.Verify(context.Background(), "00000000-0000-4000-8000-000000000005", mkSummary(0, now, now)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if stub.recorded.Mismatch {
		t.Error("mismatch=true on inverted window")
	}
	if stub.recorded.CountExpected != 0 {
		t.Errorf("expected = %d, want 0 on inverted window", stub.recorded.CountExpected)
	}
	if len(stub.auditEntries) != 0 {
		t.Error("audit fired on inverted window")
	}
}

// pg count error surfaces as a hard error so the session handler can
// log it and move on.
func TestChainVerifier_PGErrorSurfaces(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respErr: errors.New("pg down")}
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	err := v.Verify(context.Background(), "00000000-0000-4000-8000-000000000006", mkSummary(9, since, until))
	if err == nil {
		t.Fatal("Verify returned nil on pg error")
	}
	if stub.recorded.HostID != "" {
		t.Error("RecordChainSummary called on pg-count failure")
	}
}
