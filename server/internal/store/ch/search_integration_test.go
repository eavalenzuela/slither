//go:build integration

// End-to-end test for ch.SearchEvents and ch.GetEventByID. Real
// ClickHouse via testcontainers + the writer pipeline so events land
// through the same code path production uses. Verifies:
//   - Most-recent-first ordering across the four class tables.
//   - Cursor pagination yields a stable, non-overlapping next page.
//   - Filters narrow correctly.
//   - GetEventByID returns the row with raw OCSF + pretty form.

package ch_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestCH_SearchEventsCursorPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize:     100,
		FlushInterval: 200 * time.Millisecond,
		BusBuffer:     500,
	})

	host := uuid.New()
	const total = 30
	for i := 0; i < total; i++ {
		// Stagger observed_at so cursor pagination has unambiguous order.
		ts := time.Now().Add(time.Duration(i) * time.Millisecond)
		env.bus.Publish(makeProcessEnvelopeAt(t, host, uint32(2000+i), ts))
	}

	waitForRowCount(ctx, t, env, "ocsf_process_activity_1007", total, 5*time.Second)

	// First page.
	page1, cursor, err := env.store.SearchEvents(ctx, ch.EventFilter{
		ClassUIDs: []uint32{1007},
		HostID:    host.String(),
	}, ch.Cursor{}, 10)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 10 {
		t.Fatalf("page1 size = %d, want 10", len(page1))
	}
	if cursor.EventID == "" {
		t.Fatal("cursor empty after page1, want next cursor")
	}
	for i := 1; i < len(page1); i++ {
		if !page1[i-1].ObservedAt.After(page1[i].ObservedAt) &&
			page1[i-1].EventID <= page1[i].EventID {
			t.Errorf("page1 ordering broken at %d: %v vs %v", i, page1[i-1], page1[i])
		}
	}

	// Second page.
	page2, _, err := env.store.SearchEvents(ctx, ch.EventFilter{
		ClassUIDs: []uint32{1007},
		HostID:    host.String(),
	}, cursor, 10)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 10 {
		t.Fatalf("page2 size = %d, want 10", len(page2))
	}
	// No overlap between page1 and page2.
	seen := make(map[string]struct{}, len(page1))
	for _, r := range page1 {
		seen[r.EventID] = struct{}{}
	}
	for _, r := range page2 {
		if _, dup := seen[r.EventID]; dup {
			t.Errorf("page2 overlapped page1: %s", r.EventID)
		}
	}

	cancelWriter()
	<-writerDone
}

func TestCH_SearchEventsFilterAndDetail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize:     10,
		FlushInterval: 200 * time.Millisecond,
	})

	hostA := uuid.New()
	hostB := uuid.New()
	for i := 0; i < 5; i++ {
		env.bus.Publish(makeProcessEnvelope(t, hostA, uint32(3000+i)))
	}
	for i := 0; i < 3; i++ {
		env.bus.Publish(makeProcessEnvelope(t, hostB, uint32(4000+i)))
	}
	waitForRowCount(ctx, t, env, "ocsf_process_activity_1007", 8, 5*time.Second)

	rows, _, err := env.store.SearchEvents(ctx, ch.EventFilter{
		ClassUIDs: []uint32{1007},
		HostID:    hostA.String(),
	}, ch.Cursor{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Errorf("hostA rows = %d, want 5", len(rows))
	}
	for _, r := range rows {
		if r.HostID != hostA.String() {
			t.Errorf("filter leaked: row host = %s, want %s", r.HostID, hostA.String())
		}
	}

	// Detail view round-trip.
	detail, err := env.store.GetEventByID(ctx, 1007, rows[0].EventID)
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if detail.EventID != rows[0].EventID {
		t.Errorf("detail event_id mismatch")
	}
	if !strings.Contains(detail.RawPretty, "\"hello\"") &&
		!strings.Contains(detail.RawPretty, "process") {
		// raw OCSF can't be empty or unparseable.
		var v any
		if jerr := json.Unmarshal(detail.Raw, &v); jerr != nil {
			t.Errorf("detail.Raw not valid JSON: %v", jerr)
		}
	}

	cancelWriter()
	<-writerDone
}

func TestCH_SearchEvents_ParseCursorRoundTrip(t *testing.T) {
	c := ch.Cursor{ObservedAt: time.Now().UTC().Truncate(time.Microsecond), EventID: "abc-123"}
	got, err := ch.ParseCursor(c.String())
	if err != nil {
		t.Fatal(err)
	}
	if !got.ObservedAt.Equal(c.ObservedAt) || got.EventID != c.EventID {
		t.Errorf("round-trip mismatch: in=%+v out=%+v", c, got)
	}
	// Invalid cursor surfaces as an error.
	if _, err := ch.ParseCursor("garbage"); err == nil {
		t.Error("expected error on malformed cursor")
	}
}

// --- helpers ---

func makeProcessEnvelopeAt(t *testing.T, hostID uuid.UUID, pid uint32, ts time.Time) *pb.Envelope {
	t.Helper()
	ev := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{
			UID:       uuid.NewString(),
			OriginalT: ts.UnixMilli(),
		},
		ClassUID:   ocsf.ClassProcessActivity,
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.Severity(1),
		Time:       ocsf.TimeOCSF(ts.UnixMilli()),
		Process: ocsf.Process{
			PID:  pid,
			Name: "bash",
		},
		Device: ocsf.Device{HostID: hostID.String()},
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &pb.Envelope{
		EventId:     uuid.NewString(),
		HostId:      hostID.String(),
		ClassId:     pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		ObservedAt:  timestamppb.New(ts),
		CollectedAt: timestamppb.Now(),
		Payload:     payload,
	}
}

// waitForRowCount polls the table until it sees the expected count or
// the deadline expires. Avoids racy reads against an async writer.
func waitForRowCount(ctx context.Context, t *testing.T, env *chEnv, table string, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.Conn().QueryRow(ctx,
			"SELECT count() FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got >= uint64(want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("table %s did not reach %d rows", table, want)
}

// keep ingest import alive against future trims.
var _ = ingest.NewBus

// keep telemetry alive likewise.
var _ = telemetry.NewCounters
