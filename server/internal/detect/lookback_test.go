package detect

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// stubReplayer hands back a prerecorded slice of envelopes scoped to
// the requested class and time window. Tests use it to drive lookback
// without spinning up ClickHouse.
type stubReplayer struct {
	byClass map[uint32][]*pb.Envelope
	calls   int
}

func (s *stubReplayer) ReplayEnvelopes(_ context.Context, classUID uint32, since, until time.Time, fn func(*pb.Envelope) error) error {
	s.calls++
	for _, env := range s.byClass[classUID] {
		ts := env.GetObservedAt().AsTime()
		if ts.Before(since) || ts.After(until) {
			continue
		}
		if err := fn(env); err != nil {
			return err
		}
	}
	return nil
}

const lookbackCountYAML = `title: Cross-host sudo flood with lookback
id: 8b7c4d00-0001-4000-8000-000000000301
description: Three sudos for the same user inside a minute. lookback warms the window.
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() by User > 2
timeframe: 60s
cross_host: true
lookback: true
`

const noLookbackYAML = `title: Cross-host sudo flood (no lookback)
id: 8b7c4d00-0001-4000-8000-000000000302
description: Same shape but no lookback — should start cold.
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() by User > 2
timeframe: 60s
cross_host: true
`

// TestDetect_LookbackFiresOnPastEvents — three matching events
// already sitting in CH cause the rule to fire on the very first
// Refresh, before any live event arrives.
func TestDetect_LookbackFiresOnPastEvents(t *testing.T) {
	bus := ingest.NewBus(nil)
	src := &stubSource{rules: []pg.Rule{{
		UID:            "rule-lookback",
		SourceYAML:     lookbackCountYAML,
		Classification: "server_only",
	}}}
	telem := telemetry.NewCounters()
	eng := New(bus, src, telem, Options{
		BusBuffer:      32,
		FindingsBuffer: 16,
		JanitorTick:    time.Hour,
	})

	now := time.Now()
	historic := []*pb.Envelope{
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo whoami", "host-1", "alice", now.Add(-30*time.Second)),
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo whoami", "host-2", "alice", now.Add(-20*time.Second)),
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo whoami", "host-3", "alice", now.Add(-10*time.Second)),
	}
	eng.SetReplayer(&stubReplayer{byClass: map[uint32][]*pb.Envelope{
		uint32(ocsf.ClassProcessActivity): historic,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout

	select {
	case f := <-eng.Findings():
		if f.RuleID != "8b7c4d00-0001-4000-8000-000000000301" {
			t.Errorf("rule id = %q", f.RuleID)
		}
		if len(f.EventIDs) < 3 {
			t.Errorf("event_ids = %d, want >=3 (lookback should have replayed all 3)", len(f.EventIDs))
		}
	case <-time.After(time.Second):
		t.Fatalf("lookback never fired (telemetry: events=%d findings=%d)",
			telem.Snapshot().DetectEvents, telem.Snapshot().DetectFindings)
	}
}

// TestDetect_NoLookbackStartsCold — a rule without lookback: true
// doesn't fire from past events even when the replayer is wired up.
// (Defensive: our engine should never replay a non-opt-in rule.)
func TestDetect_NoLookbackStartsCold(t *testing.T) {
	bus := ingest.NewBus(nil)
	src := &stubSource{rules: []pg.Rule{{
		UID:            "rule-cold",
		SourceYAML:     noLookbackYAML,
		Classification: "server_only",
	}}}
	telem := telemetry.NewCounters()
	eng := New(bus, src, telem, Options{
		BusBuffer:      32,
		FindingsBuffer: 16,
		JanitorTick:    time.Hour,
	})
	now := time.Now()
	historic := []*pb.Envelope{
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo", "host-1", "alice", now.Add(-30*time.Second)),
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo", "host-2", "alice", now.Add(-20*time.Second)),
		makeProcessEnvelope(t, "/usr/bin/sudo", "sudo", "host-3", "alice", now.Add(-10*time.Second)),
	}
	replayer := &stubReplayer{byClass: map[uint32][]*pb.Envelope{
		uint32(ocsf.ClassProcessActivity): historic,
	}}
	eng.SetReplayer(replayer)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout

	select {
	case f := <-eng.Findings():
		t.Errorf("non-lookback rule should not fire on historic events: %+v", f)
	case <-time.After(150 * time.Millisecond):
	}
	if replayer.calls != 0 {
		t.Errorf("replayer should not be called for non-lookback rules; calls=%d", replayer.calls)
	}
}

// TestDetect_LookbackSkippedOverMaxLookback — a rule with timeframe
// > MaxLookback skips lookback even when opt-in.
func TestDetect_LookbackSkippedOverMaxLookback(t *testing.T) {
	const longWindowYAML = `title: long
id: 8b7c4d00-0001-4000-8000-000000000303
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() by User > 2
timeframe: 5m
cross_host: true
lookback: true
`
	bus := ingest.NewBus(nil)
	src := &stubSource{rules: []pg.Rule{{
		UID:            "rule-overmax",
		SourceYAML:     longWindowYAML,
		Classification: "server_only",
	}}}
	telem := telemetry.NewCounters()
	eng := New(bus, src, telem, Options{
		BusBuffer:      32,
		FindingsBuffer: 16,
		JanitorTick:    time.Hour,
		MaxLookback:    time.Minute, // 5m > 1m → skip
	})
	replayer := &stubReplayer{}
	eng.SetReplayer(replayer)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout

	// Give Refresh time to consider lookback.
	time.Sleep(50 * time.Millisecond)
	if replayer.calls != 0 {
		t.Errorf("over-MaxLookback timeframe should skip replay; calls=%d", replayer.calls)
	}
}

// makeProcessEnvelope builds an Envelope with a stamped observed_at
// so lookback can use it as the tick clock.
func makeProcessEnvelope(t *testing.T, image, cmdline, hostID, user string, observedAt time.Time) *pb.Envelope {
	t.Helper()
	env := processEnvelope(t, image, cmdline, hostID, user)
	env.ObservedAt = timestamppb.New(observedAt)
	return env
}
