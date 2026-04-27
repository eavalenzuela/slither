package detect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// stubWriter records every InsertAlert call and lets the test
// preconfigure a dedupe path or a hard error. It's safe for
// concurrent use because the sink runs alone but tests still poll it
// while sending findings.
type stubWriter struct {
	mu        sync.Mutex
	inserts   []pg.AlertInsert
	deduped   bool
	err       error
	dedupeSec int
}

func (s *stubWriter) InsertAlert(_ context.Context, ins pg.AlertInsert) (pg.AlertInsertResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inserts = append(s.inserts, ins)
	if s.err != nil {
		return pg.AlertInsertResult{}, s.err
	}
	if s.deduped {
		return pg.AlertInsertResult{
			DedupeWindowSecs: s.dedupeSec,
			DedupeSuppressed: true,
		}, nil
	}
	return pg.AlertInsertResult{
		Inserted: true,
		AlertID:  uuid.New(),
	}, nil
}

// stubTelem captures the per-outcome counter bumps the sink should
// produce. Plain ints are fine — the sink runs in a single goroutine.
type stubTelem struct {
	inserted int
	deduped  int
	errored  int
}

func (s *stubTelem) IncAlertsInserted() { s.inserted++ }
func (s *stubTelem) IncAlertsDeduped()  { s.deduped++ }
func (s *stubTelem) IncAlertsErrored()  { s.errored++ }

// sample finding helpers — the alerts table requires host_id, so all
// fixtures populate it.
func sampleFinding() Finding {
	return Finding{
		RuleID:   "rule-x",
		HostID:   "11111111-1111-4111-8111-111111111111",
		Severity: 4,
		EventIDs: []string{"22222222-2222-4222-8222-222222222222"},
		Reason:   "test",
	}
}

// TestSink_InsertsHappyPath drives one finding and asserts the
// writer saw it and the inserted counter ticked.
func TestSink_InsertsHappyPath(t *testing.T) {
	w := &stubWriter{}
	tel := &stubTelem{}
	ch := make(chan Finding, 1)
	ch <- sampleFinding()
	close(ch)

	if err := RunFindingsSink(context.Background(), ch, w, tel); err != nil {
		t.Fatalf("sink: %v", err)
	}
	if got := len(w.inserts); got != 1 {
		t.Errorf("inserts = %d, want 1", got)
	}
	if tel.inserted != 1 || tel.deduped != 0 || tel.errored != 0 {
		t.Errorf("telem inserted=%d deduped=%d errored=%d, want 1/0/0", tel.inserted, tel.deduped, tel.errored)
	}
}

// TestSink_RecordsDedupe — when the writer signals dedupe, the sink
// bumps deduped and not inserted.
func TestSink_RecordsDedupe(t *testing.T) {
	w := &stubWriter{deduped: true, dedupeSec: 60}
	tel := &stubTelem{}
	ch := make(chan Finding, 1)
	ch <- sampleFinding()
	close(ch)

	_ = RunFindingsSink(context.Background(), ch, w, tel)
	if tel.deduped != 1 || tel.inserted != 0 {
		t.Errorf("telem inserted=%d deduped=%d, want 0/1", tel.inserted, tel.deduped)
	}
}

// TestSink_LogsErrorButContinues — a failing write doesn't take down
// the sink; subsequent findings still reach the writer.
func TestSink_LogsErrorButContinues(t *testing.T) {
	w := &stubWriter{err: errors.New("transient pg")}
	tel := &stubTelem{}
	ch := make(chan Finding, 2)
	ch <- sampleFinding()
	ch <- sampleFinding()
	close(ch)

	_ = RunFindingsSink(context.Background(), ch, w, tel)
	if tel.errored != 2 {
		t.Errorf("errored = %d, want 2", tel.errored)
	}
	if tel.inserted != 0 {
		t.Errorf("no row should have landed; inserted = %d", tel.inserted)
	}
}

// TestSink_DropsCrossHostFindings — alerts.host_id is NOT NULL, so a
// finding with no HostID can't land. The sink logs and skips rather
// than calling InsertAlert.
func TestSink_DropsCrossHostFindings(t *testing.T) {
	w := &stubWriter{}
	tel := &stubTelem{}
	f := sampleFinding()
	f.HostID = ""
	ch := make(chan Finding, 1)
	ch <- f
	close(ch)

	_ = RunFindingsSink(context.Background(), ch, w, tel)
	if got := len(w.inserts); got != 0 {
		t.Errorf("InsertAlert should not be called for host-less finding; got %d calls", got)
	}
	if tel.inserted != 0 || tel.deduped != 0 || tel.errored != 0 {
		t.Errorf("counters should all be zero; got %+v", tel)
	}
}

// TestSink_RespectsCancel — closing ctx returns the sink even when
// the channel still has buffered findings.
func TestSink_RespectsCancel(t *testing.T) {
	w := &stubWriter{}
	tel := &stubTelem{}
	ch := make(chan Finding) // unbuffered, never delivered
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunFindingsSink(ctx, ch, w, tel) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sink did not exit on cancel")
	}
}
