package detect

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// stubSource lets tests inject rules without spinning up Postgres.
type stubSource struct {
	rules []pg.Rule
}

func (s *stubSource) ListEnabledRules(_ context.Context) ([]pg.Rule, error) {
	out := make([]pg.Rule, len(s.rules))
	copy(out, s.rules)
	return out, nil
}

const crossHostCountYAML = `title: Per-user sudo flood (cross-host)
id: 8b7c4d00-0001-4000-8000-000000000201
description: Same user firing sudo three times across the fleet inside a minute.
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

const nearJoinYAML = `title: wget then chmod within 30s
id: 8b7c4d00-0001-4000-8000-000000000202
description: A fetch followed by a chmod making the file executable.
level: high
logsource:
  product: linux
  category: process_creation
detection:
  fetch:
    Image|endswith: /usr/bin/wget
  chmod_exec:
    Image|endswith: /usr/bin/chmod
    CommandLine|contains: '+x'
  condition: fetch near chmod_exec
timeframe: 30s
`

func processEnvelope(t *testing.T, image, cmdline, hostID, user string) *pb.Envelope {
	t.Helper()
	ts := time.Now().UnixMilli()
	ev := &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: uuid.NewString()},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: hostID},
		Process: ocsf.Process{
			PID:     1234,
			Cmdline: cmdline,
			File:    &ocsf.File{Path: image},
			User:    &ocsf.User{Name: user},
		},
		Actor: ocsf.Actor{User: ocsf.User{Name: user}},
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return &pb.Envelope{
		EventId: uuid.NewString(),
		HostId:  hostID,
		ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		Payload: payload,
	}
}

func newEngineWith(t *testing.T, yamls ...string) (*Engine, *ingest.Bus, *telemetry.Counters) {
	t.Helper()
	bus := ingest.NewBus(nil)
	rules := make([]pg.Rule, len(yamls))
	for i, y := range yamls {
		rules[i] = pg.Rule{
			UID:            "rule-" + string(rune('a'+i)),
			SourceYAML:     y,
			Classification: "server_only",
		}
	}
	src := &stubSource{rules: rules}
	telem := telemetry.NewCounters()
	eng := New(bus, src, telem, Options{
		BusBuffer:      32,
		FindingsBuffer: 16,
		JanitorTick:    time.Hour, // suppress janitor in tests
	})
	return eng, bus, telem
}

// TestDetect_CountThresholdFires — three matching events from
// different hosts but the same user cross the > 2 threshold.
func TestDetect_CountThresholdFires(t *testing.T) {
	eng, bus, telem := newEngineWith(t, crossHostCountYAML)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout

	// Wait briefly for Subscribe to register.
	time.Sleep(20 * time.Millisecond)

	for i := 0; i < 3; i++ {
		bus.Publish(processEnvelope(t, "/usr/bin/sudo", "sudo whoami", "host-"+string(rune('1'+i)), "alice"))
	}
	select {
	case f := <-eng.Findings():
		if f.RuleID != "8b7c4d00-0001-4000-8000-000000000201" {
			t.Errorf("rule id = %q", f.RuleID)
		}
		if f.GroupKey != "alice" {
			t.Errorf("group_key = %q, want alice", f.GroupKey)
		}
		if len(f.EventIDs) < 3 {
			t.Errorf("event_ids = %d, want >=3", len(f.EventIDs))
		}
	case <-time.After(time.Second):
		t.Fatalf("finding never fired (telemetry: events=%d findings=%d)", telem.Snapshot().DetectEvents, telem.Snapshot().DetectFindings)
	}
}

// TestDetect_CountUnderThreshold — two events of three required don't fire.
func TestDetect_CountUnderThreshold(t *testing.T) {
	eng, bus, _ := newEngineWith(t, crossHostCountYAML)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout
	time.Sleep(20 * time.Millisecond)

	for i := 0; i < 2; i++ {
		bus.Publish(processEnvelope(t, "/usr/bin/sudo", "sudo whoami", "host-1", "alice"))
	}
	select {
	case f := <-eng.Findings():
		t.Errorf("unexpected finding: %+v", f)
	case <-time.After(150 * time.Millisecond):
		// Good — no finding, threshold (>2) not crossed.
	}
}

// TestDetect_NearJoinFires — fetch followed by chmod inside the
// 30s window correlates and fires.
func TestDetect_NearJoinFires(t *testing.T) {
	eng, bus, _ := newEngineWith(t, nearJoinYAML)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout
	time.Sleep(20 * time.Millisecond)

	bus.Publish(processEnvelope(t, "/usr/bin/wget", "wget http://x", "host-1", "root"))
	bus.Publish(processEnvelope(t, "/usr/bin/chmod", "chmod +x /tmp/x", "host-1", "root"))

	select {
	case f := <-eng.Findings():
		if f.RuleID != "8b7c4d00-0001-4000-8000-000000000202" {
			t.Errorf("rule id = %q", f.RuleID)
		}
		if f.GroupKey != "fetch→chmod_exec" {
			t.Errorf("group_key = %q", f.GroupKey)
		}
	case <-time.After(time.Second):
		t.Fatal("near join never fired")
	}
}

// TestDetect_NearJoinSkipsUnpaired — only one side matching doesn't fire.
func TestDetect_NearJoinSkipsUnpaired(t *testing.T) {
	eng, bus, _ := newEngineWith(t, nearJoinYAML)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout
	time.Sleep(20 * time.Millisecond)

	// Only the fetch arm — chmod never arrives.
	bus.Publish(processEnvelope(t, "/usr/bin/wget", "wget http://x", "host-1", "root"))
	select {
	case f := <-eng.Findings():
		t.Errorf("unexpected finding from one-sided near: %+v", f)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestDetect_FindingsBackpressureDoesNotBlockBus — a slow findings
// consumer drops findings rather than stalling ingest.
func TestDetect_FindingsBackpressureDoesNotBlockBus(t *testing.T) {
	bus := ingest.NewBus(nil)
	src := &stubSource{rules: []pg.Rule{{
		UID:            "rule-a",
		SourceYAML:     crossHostCountYAML,
		Classification: "server_only",
	}}}
	telem := telemetry.NewCounters()
	eng := New(bus, src, telem, Options{
		BusBuffer:      32,
		FindingsBuffer: 1, // very small so backpressure is easy to trip
		JanitorTick:    time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx) //nolint:errcheck // engine errs surface via channel close + tests assert via timeout
	time.Sleep(20 * time.Millisecond)

	// Drive ~30 above-threshold bursts. Each burst of 3 sudo events
	// fires a finding; the 1-deep findings channel saturates fast.
	for burst := 0; burst < 30; burst++ {
		for i := 0; i < 3; i++ {
			bus.Publish(processEnvelope(t, "/usr/bin/sudo", "x", "host-1", "alice"))
		}
	}
	// Give the engine time to process.
	time.Sleep(200 * time.Millisecond)

	snap := telem.Snapshot()
	if snap.DetectFindingsDropped == 0 {
		t.Errorf("DetectFindingsDropped = 0, want >0 (backpressure should have triggered)")
	}
}
