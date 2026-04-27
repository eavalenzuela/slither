package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

type stubWriter struct {
	mu      sync.Mutex
	inserts []pg.AlertInsert
	deduped bool
	err     error
}

func (s *stubWriter) InsertAlert(_ context.Context, ins pg.AlertInsert) (pg.AlertInsertResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inserts = append(s.inserts, ins)
	if s.err != nil {
		return pg.AlertInsertResult{}, s.err
	}
	if s.deduped {
		return pg.AlertInsertResult{DedupeSuppressed: true, DedupeWindowSecs: 60}, nil
	}
	return pg.AlertInsertResult{Inserted: true, AlertID: uuid.New()}, nil
}

func (s *stubWriter) snapshot() []pg.AlertInsert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]pg.AlertInsert, len(s.inserts))
	copy(out, s.inserts)
	return out
}

type stubTelem struct {
	mu                         sync.Mutex
	inserted, deduped, errored int
}

func (s *stubTelem) IncAlertsInserted() { s.mu.Lock(); s.inserted++; s.mu.Unlock() }
func (s *stubTelem) IncAlertsDeduped()  { s.mu.Lock(); s.deduped++; s.mu.Unlock() }
func (s *stubTelem) IncAlertsErrored()  { s.mu.Lock(); s.errored++; s.mu.Unlock() }

func makeDetectionFindingEnvelope(t *testing.T, ruleUID, hostID string, eventIDs []string, severity ocsf.Severity) *pb.Envelope {
	t.Helper()
	finding := &ocsf.DetectionFinding{
		ClassUID:           ocsf.ClassDetectionFinding,
		Severity:           severity,
		Finding:            ocsf.Finding{Title: "Test rule fired"},
		RuleInfo:           ocsf.Rule{UID: ruleUID, Name: "Test"},
		TriggeringEventIDs: eventIDs,
	}
	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	return &pb.Envelope{
		EventId: uuid.NewString(),
		HostId:  hostID,
		ClassId: pb.OcsfClassId(ocsf.ClassDetectionFinding),
		Payload: payload,
	}
}

func TestRouteAlerts_RoutesDetectionFindings(t *testing.T) {
	bus := NewBus(nil)
	t.Cleanup(bus.Close)
	w := &stubWriter{}
	tel := &stubTelem{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RouteAlerts(ctx, bus, "test-router", w, tel) }()

	// Wait for Subscribe to register before publishing.
	time.Sleep(20 * time.Millisecond)

	bus.Publish(makeDetectionFindingEnvelope(t, "rule-x",
		"11111111-1111-4111-8111-111111111111",
		[]string{"22222222-2222-4222-8222-222222222222"},
		ocsf.SeverityHigh))

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(w.snapshot()) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	got := w.snapshot()
	if len(got) != 1 {
		t.Fatalf("inserts = %d, want 1", len(got))
	}
	if got[0].RuleUID != "rule-x" {
		t.Errorf("rule_uid = %q", got[0].RuleUID)
	}
	if got[0].HostID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("host_id = %q", got[0].HostID)
	}
	if tel.inserted != 1 {
		t.Errorf("telem inserted = %d, want 1", tel.inserted)
	}
}

func TestRouteAlerts_IgnoresNonFindingEnvelopes(t *testing.T) {
	bus := NewBus(nil)
	t.Cleanup(bus.Close)
	w := &stubWriter{}
	tel := &stubTelem{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RouteAlerts(ctx, bus, "test-router", w, tel) }()
	time.Sleep(20 * time.Millisecond)

	// Publish a non-finding envelope (process activity).
	bus.Publish(&pb.Envelope{
		EventId: uuid.NewString(),
		HostId:  "11111111-1111-4111-8111-111111111111",
		ClassId: pb.OcsfClassId(ocsf.ClassProcessActivity),
		Payload: []byte(`{"class_uid":1007}`),
	})
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if got := len(w.snapshot()); got != 0 {
		t.Errorf("non-finding envelope routed: %d inserts", got)
	}
}

func TestRouteAlerts_LogsAndContinuesOnInsertError(t *testing.T) {
	bus := NewBus(nil)
	t.Cleanup(bus.Close)
	w := &stubWriter{err: errors.New("pg down")}
	tel := &stubTelem{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RouteAlerts(ctx, bus, "test-router", w, tel) }()
	time.Sleep(20 * time.Millisecond)

	bus.Publish(makeDetectionFindingEnvelope(t, "rule-x",
		"11111111-1111-4111-8111-111111111111",
		[]string{"22222222-2222-4222-8222-222222222222"},
		ocsf.SeverityHigh))
	bus.Publish(makeDetectionFindingEnvelope(t, "rule-y",
		"11111111-1111-4111-8111-111111111111",
		nil, ocsf.SeverityMedium))

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		tel.mu.Lock()
		got := tel.errored
		tel.mu.Unlock()
		if got >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	tel.mu.Lock()
	defer tel.mu.Unlock()
	if tel.errored != 2 {
		t.Errorf("errored = %d, want 2 (router should keep going)", tel.errored)
	}
}
