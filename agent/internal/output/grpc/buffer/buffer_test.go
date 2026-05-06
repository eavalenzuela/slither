package buffer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func mkEnv(eventID string, observedAt time.Time) *pb.Envelope {
	return &pb.Envelope{
		EventId:    eventID,
		HostId:     "host-1",
		ObservedAt: timestamppb.New(observedAt),
	}
}

func TestBuffer_AppendThenReplayRoundTrip(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	b, err := Open(Options{Dir: tmp})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	now := time.Now()
	for i := 0; i < 5; i++ {
		if _, appendErr := b.Append(mkEnv(fmt.Sprintf("ev-%d", i), now)); appendErr != nil {
			t.Fatalf("Append %d: %v", i, appendErr)
		}
	}
	// Force rotation so the first segment becomes sealed (replay
	// only walks sealed segments to avoid racing with a concurrent
	// Append in the live integration). Touching SegmentBytes would
	// be cleaner but requires a re-Open; rotateLocked isn't exported.
	// Instead: close + reopen to seal.
	b.Close()
	b2, err := Open(Options{Dir: tmp})
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer b2.Close()

	var seen []string
	replayed, dropped, err := b2.Replay(func(env *pb.Envelope) error {
		seen = append(seen, env.GetEventId())
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed != 5 || dropped != 0 {
		t.Errorf("replayed=%d dropped=%d, want 5/0", replayed, dropped)
	}
	for i, id := range seen {
		want := fmt.Sprintf("ev-%d", i)
		if id != want {
			t.Errorf("seen[%d]=%s, want %s", i, id, want)
		}
	}

	// Replayed segments are deleted; Replay again is a no-op.
	r2, _, _ := b2.Replay(func(*pb.Envelope) error { return nil })
	if r2 != 0 {
		t.Errorf("second Replay = %d, want 0", r2)
	}
}

func TestBuffer_SegmentRotationOnSize(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Force a tiny segment cap so a few appends rotate.
	b, err := Open(Options{Dir: tmp, SegmentBytes: 256})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	now := time.Now()
	for i := 0; i < 20; i++ {
		// Each Envelope ~50-60 bytes serialised + 4 byte len = ~60 bytes;
		// 20 of them = ~1200 bytes → ~5 segments at 256-byte cap.
		if _, err := b.Append(mkEnv(fmt.Sprintf("ev-%d", i), now)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Without forcing close, only sealed segments show up — but
	// rotation already flipped a few. Count files in dir.
	entries, _ := os.ReadDir(tmp)
	if len(entries) < 2 {
		t.Errorf("expected at least 2 segment files after 20 appends @ 256-byte cap, got %d", len(entries))
	}
}

func TestBuffer_OldestWinsEviction(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Tiny segments + tiny total cap so a few writes evict.
	b, err := Open(Options{Dir: tmp, SegmentBytes: 200, MaxBytes: 600})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	now := time.Now()
	for i := 0; i < 50; i++ {
		if _, err := b.Append(mkEnv(fmt.Sprintf("ev-%d", i), now)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Total bytes on disk should now be <= MaxBytes (with one active
	// segment exempt — that one can exceed the cap by up to its own
	// segment size).
	entries, _ := os.ReadDir(tmp)
	var total int64
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		total += fi.Size()
	}
	if total > 600+200 { // MaxBytes + one segment slack
		t.Errorf("disk total = %d bytes, want <= ~800 (MaxBytes %d + 1 active segment)", total, 600)
	}
}

func TestBuffer_StaleRecordsDropped(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	b, err := Open(Options{Dir: tmp, MaxAge: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	stale := time.Now().Add(-1 * time.Hour)
	fresh := time.Now()
	if _, appendErr := b.Append(mkEnv("stale-1", stale)); appendErr != nil {
		t.Fatalf("Append stale: %v", appendErr)
	}
	if _, appendErr := b.Append(mkEnv("fresh-1", fresh)); appendErr != nil {
		t.Fatalf("Append fresh: %v", appendErr)
	}
	b.Close()

	b2, _ := Open(Options{Dir: tmp, MaxAge: 100 * time.Millisecond})
	defer b2.Close()

	var seen []string
	r, d, err := b2.Replay(func(env *pb.Envelope) error {
		seen = append(seen, env.GetEventId())
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if r != 1 || d != 1 {
		t.Errorf("replayed=%d dropped=%d, want 1/1", r, d)
	}
	if len(seen) != 1 || seen[0] != "fresh-1" {
		t.Errorf("seen = %v, want [fresh-1]", seen)
	}
}

func TestBuffer_RestartContinuesCounter(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	b1, _ := Open(Options{Dir: tmp, SegmentBytes: 100})
	now := time.Now()
	for i := 0; i < 10; i++ {
		_, _ = b1.Append(mkEnv(fmt.Sprintf("a-%d", i), now))
	}
	b1.Close()

	b2, err := Open(Options{Dir: tmp, SegmentBytes: 100})
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer b2.Close()
	for i := 0; i < 5; i++ {
		_, _ = b2.Append(mkEnv(fmt.Sprintf("b-%d", i), now))
	}

	// All 15 events should be replayable post-restart.
	b2.Close()
	b3, _ := Open(Options{Dir: tmp})
	defer b3.Close()
	r, _, err := b3.Replay(func(env *pb.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if r != 15 {
		t.Errorf("replayed = %d after restart, want 15", r)
	}
}

func TestBuffer_ConsumeErrorStopsReplayAndPreservesSegment(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	b, err := Open(Options{Dir: tmp, SegmentBytes: 80})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	now := time.Now()
	for i := 0; i < 10; i++ {
		_, _ = b.Append(mkEnv(fmt.Sprintf("ev-%d", i), now))
	}
	b.Close()

	b2, _ := Open(Options{Dir: tmp})
	defer b2.Close()

	wantErr := errors.New("simulated server unreachable")
	count := 0
	r, _, err := b2.Replay(func(env *pb.Envelope) error {
		count++
		if count == 3 {
			return wantErr
		}
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Replay err = %v, want %v", err, wantErr)
	}
	if r != 2 {
		t.Errorf("replayed = %d before error, want 2", r)
	}

	// At least one segment file should remain on disk (the one we
	// failed in, and any after it).
	entries, _ := os.ReadDir(tmp)
	if len(entries) < 1 {
		t.Errorf("expected segments to remain after consume error; got %d entries", len(entries))
	}
}

func TestBuffer_NilEnvelopeIsNoOp(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	b, _ := Open(Options{Dir: tmp})
	defer b.Close()
	n, err := b.Append(nil)
	if err != nil {
		t.Errorf("Append(nil) = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("Append(nil) = %d bytes, want 0", n)
	}
}

func TestBuffer_OpenWithoutDirErrors(t *testing.T) {
	t.Parallel()
	if _, err := Open(Options{}); err == nil {
		t.Error("Open without Dir = nil error, want error")
	}
}

func TestParseSegmentName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		ok   bool
		want uint64
	}{
		{"seg-0000000000000000.dat", true, 0},
		{"seg-0000000000000042.dat", true, 42},
		{"seg-9999999999999999.dat", true, 9999999999999999},
		{"seg-0000000000000042.bin", false, 0},
		{"seg-abc.dat", false, 0},
		{"random.txt", false, 0},
	}
	for _, c := range cases {
		got, ok := parseSegmentName(c.in)
		if ok != c.ok {
			t.Errorf("parseSegmentName(%q) ok=%v, want %v", c.in, ok, c.ok)
		}
		if c.ok && got != c.want {
			t.Errorf("parseSegmentName(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
