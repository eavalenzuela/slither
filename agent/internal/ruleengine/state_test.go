package ruleengine

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

const sudoFloodSigma = `title: Sudo flood
id: 99999999-9999-4999-8999-999999999991
description: Five sudo events from a single host inside a minute.
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() > 4
timeframe: 60s
`

const sudoByUserSigma = `title: Per-user sudo flood
id: 99999999-9999-4999-8999-999999999992
description: Three sudo events per user in five minutes.
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() by User >= 3
timeframe: 5m
`

func sudoEvent(user string) *ocsf.ProcessActivity {
	return processActivityForSudo(user)
}

func processActivityForSudo(user string) *ocsf.ProcessActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-sudo"},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Process: ocsf.Process{
			PID:     1000,
			Name:    "sudo",
			Cmdline: "sudo whoami",
			File:    &ocsf.File{Path: "/usr/bin/sudo"},
			User:    &ocsf.User{Name: user, UID: "0"},
		},
		Actor: ocsf.Actor{User: ocsf.User{Name: user}},
	}
}

// fakeNow returns a clock the test can advance manually so window-edge
// behaviour is deterministic.
type fakeNow struct{ t time.Time }

func (f *fakeNow) Now() time.Time          { return f.t }
func (f *fakeNow) advance(d time.Duration) { f.t = f.t.Add(d) }

// withFakeClock swaps the rule's now() function for the test clock and
// returns a restore func.
func withFakeClock(scr *sigmaCompiledRule, fn func() time.Time) func() {
	prev := scr.now
	scr.now = fn
	return func() { scr.now = prev }
}

// TestStatefulCountThresholdCrossing — first four events do nothing,
// fifth crosses the >4 threshold and fires.
func TestStatefulCountThresholdCrossing(t *testing.T) {
	rule := compileFixture(t, sudoFloodSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	scr := rules[0].(*sigmaCompiledRule)

	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 4; i++ {
		if scr.Match(sudoEvent("alice")) {
			t.Fatalf("event %d should not fire (under threshold)", i+1)
		}
		clk.advance(5 * time.Second)
	}
	if !scr.Match(sudoEvent("alice")) {
		t.Errorf("5th sudo within window should cross >4 threshold")
	}
}

// TestStatefulWindowExpires — events older than timeframe are dropped
// from the count.
func TestStatefulWindowExpires(t *testing.T) {
	rule := compileFixture(t, sudoFloodSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scr := rules[0].(*sigmaCompiledRule)

	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 4; i++ {
		scr.Match(sudoEvent("alice"))
		clk.advance(5 * time.Second)
	}
	// Jump past the 60s window; previous 4 events should be expired.
	clk.advance(120 * time.Second)
	// Three more events in the new window — still under threshold (>4).
	for i := 0; i < 3; i++ {
		if scr.Match(sudoEvent("alice")) {
			t.Errorf("event after window expiry should not fire (count=%d)", i+1)
		}
		clk.advance(1 * time.Second)
	}
}

// TestStatefulByUserPartitions — each user has its own count; alice
// hitting threshold doesn't make bob's count cross.
func TestStatefulByUserPartitions(t *testing.T) {
	rule := compileFixture(t, sudoByUserSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scr := rules[0].(*sigmaCompiledRule)

	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	// Alice: 3 events — should fire on the 3rd (>=3).
	for i := 0; i < 2; i++ {
		if scr.Match(sudoEvent("alice")) {
			t.Errorf("alice event %d should not fire", i+1)
		}
		clk.advance(1 * time.Second)
	}
	if !scr.Match(sudoEvent("alice")) {
		t.Errorf("alice 3rd event should fire (>=3)")
	}

	// Bob: a single event — under threshold, should not fire.
	if scr.Match(sudoEvent("bob")) {
		t.Errorf("bob's first event should not fire")
	}
}

// TestStatefulCapEviction — exceeding the 1024-key cap drops the
// least-recently-touched key and bumps state_evicted.
func TestStatefulCapEviction(t *testing.T) {
	rule := compileFixture(t, sudoByUserSigma)
	telem := telemetry.NewCounters()
	rules, err := CompileRules([]*ruleast.Rule{rule}, telem, nil)
	if err != nil {
		t.Fatal(err)
	}
	scr := rules[0].(*sigmaCompiledRule)
	// Tighten cap manually to keep the test small; the production cap
	// is 1024 but the eviction logic is identical at any positive size.
	scr.state.maxKeys = 4

	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for _, u := range []string{"u1", "u2", "u3", "u4"} {
		scr.Match(sudoEvent(u))
		clk.advance(1 * time.Second)
	}
	if got := telem.Snapshot().StateEvicted; got != 0 {
		t.Errorf("StateEvicted = %d before overflow, want 0", got)
	}
	// 5th distinct user — should evict u1 (LRU).
	scr.Match(sudoEvent("u5"))
	if got := telem.Snapshot().StateEvicted; got != 1 {
		t.Errorf("StateEvicted = %d after one overflow, want 1", got)
	}
	if _, ok := scr.state.keys["u1"]; ok {
		t.Errorf("u1 should have been evicted (LRU)")
	}
	if _, ok := scr.state.keys["u5"]; !ok {
		t.Errorf("u5 should be present after overflow eviction")
	}
}

// TestStatefulSweepReclaimsExpiredKeys — sweep removes keys whose
// timestamps have all expired so memory doesn't bloat between matches.
func TestStatefulSweepReclaimsExpiredKeys(t *testing.T) {
	rule := compileFixture(t, sudoByUserSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scr := rules[0].(*sigmaCompiledRule)

	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()
	scr.Match(sudoEvent("ghost"))

	if _, ok := scr.state.keys["ghost"]; !ok {
		t.Fatalf("expected key after one tick")
	}

	// Past the 5m window, ghost's timestamps are stale; sweep should
	// reclaim the key entirely.
	clk.advance(10 * time.Minute)
	scr.state.sweep(clk.Now())
	if _, ok := scr.state.keys["ghost"]; ok {
		t.Errorf("expired key should have been reaped by sweep")
	}
}

// TestStatefulRestartClearsState — a fresh CompileRules call produces
// a rule with empty state, even if the underlying YAML is identical.
func TestStatefulRestartClearsState(t *testing.T) {
	first, err := CompileRules([]*ruleast.Rule{compileFixture(t, sudoByUserSigma)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	scrFirst := first[0].(*sigmaCompiledRule)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scrFirst, clk.Now)()
	for i := 0; i < 5; i++ {
		scrFirst.Match(sudoEvent("alice"))
	}
	if got := len(scrFirst.state.keys["alice"].timestamps); got == 0 {
		t.Errorf("first instance should have recorded timestamps; got %d", got)
	}

	// Simulate restart: build a brand-new compiled rule from the same YAML.
	second, err := CompileRules([]*ruleast.Rule{compileFixture(t, sudoByUserSigma)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	scrSecond := second[0].(*sigmaCompiledRule)
	if got := len(scrSecond.state.keys); got != 0 {
		t.Errorf("freshly-compiled rule should start empty; got %d keys", got)
	}
}

// TestStatefulConcurrentTickRace — exercise the lock under concurrent
// Match calls. -race catches missing synchronisation.
func TestStatefulConcurrentTickRace(t *testing.T) {
	rule := compileFixture(t, sudoByUserSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scr := rules[0].(*sigmaCompiledRule)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			scr.Match(sudoEvent("alice"))
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		scr.state.sweep(time.Now())
	}
	<-done
}
