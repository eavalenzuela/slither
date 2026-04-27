package control

import (
	"context"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// stubSource serves rules from an in-memory slice. Swapping the slice
// before Refresh simulates a Postgres update without a DB.
type stubSource struct {
	rules []pg.Rule
}

func (s *stubSource) ListEnabledRules(_ context.Context) ([]pg.Rule, error) {
	out := make([]pg.Rule, len(s.rules))
	copy(out, s.rules)
	return out, nil
}

const sampleYAML = `title: Test rule
id: 11111111-1111-4111-8111-111111111111
description: Test
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /bin/bash
  condition: selection
`

func TestHub_RefreshAndSubscribe(t *testing.T) {
	src := &stubSource{rules: []pg.Rule{{
		UID: "rule-1", Name: "Test rule", SourceYAML: sampleYAML,
	}}}
	hub := NewHub(src, telemetry.NewCounters())

	if _, err := hub.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	rs := hub.Current()
	if rs == nil || len(rs.GetRules()) != 1 {
		t.Fatalf("current ruleset = %+v", rs)
	}
	if rs.GetRules()[0].GetRuleId() != "rule-1" {
		t.Errorf("rule_id = %q", rs.GetRules()[0].GetRuleId())
	}
	if rs.GetRules()[0].GetAstVersion() != astVersionStateless {
		t.Errorf("ast_version = %d, want %d", rs.GetRules()[0].GetAstVersion(), astVersionStateless)
	}

	// Subscribe — initial RuleSet must arrive synchronously.
	ch := hub.Subscribe("agent-1")
	select {
	case got := <-ch:
		if got != rs {
			t.Errorf("initial ruleset mismatch")
		}
	default:
		t.Fatal("no initial ruleset delivered to new subscriber")
	}
}

func TestHub_FanOutAndDropOldest(t *testing.T) {
	src := &stubSource{rules: []pg.Rule{{
		UID: "rule-1", SourceYAML: sampleYAML,
	}}}
	hub := NewHub(src, telemetry.NewCounters())
	if _, err := hub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	a := hub.Subscribe("a")
	b := hub.Subscribe("b")

	// Drain initials.
	<-a
	<-b

	// Multiple Refreshes fanned out — slow subscriber sees only the
	// latest because channel cap is 1 and Publish drains stale.
	for i := 0; i < 5; i++ {
		if _, err := hub.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	gotA := <-a
	gotB := <-b
	if gotA != hub.Current() || gotB != hub.Current() {
		t.Errorf("subscribers did not converge to latest ruleset")
	}
}

func TestHub_SkipUncompilableRule(t *testing.T) {
	src := &stubSource{rules: []pg.Rule{
		{UID: "good", SourceYAML: sampleYAML},
		{UID: "bad", SourceYAML: "not valid sigma yaml ::: {{}}"},
	}}
	hub := NewHub(src, telemetry.NewCounters())
	skipped, err := hub.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if got := len(hub.Current().GetRules()); got != 1 {
		t.Errorf("rules emitted = %d, want 1 (the compilable one)", got)
	}
}

func TestHub_UnsubscribeClosesChannel(t *testing.T) {
	hub := NewHub(&stubSource{}, telemetry.NewCounters())
	ch := hub.Subscribe("x")
	hub.Unsubscribe("x")
	if _, ok := <-ch; ok {
		t.Errorf("channel should be closed after Unsubscribe")
	}
}

const statefulYAML = `title: Stateful test rule
id: 22222222-2222-4222-8222-222222222222
description: Bounded-stateful rule that should ride ast_version=2.
level: high
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() > 5
timeframe: 60s
`

const serverOnlyYAML = `title: Server-only test rule
id: 33333333-3333-4333-8333-333333333333
description: Cross-host aggregation — should be filtered out of the wire payload.
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /usr/bin/sudo
  condition: selection | count() by User > 5
timeframe: 60s
cross_host: true
`

func TestHub_EmitsStatefulV2Bounds(t *testing.T) {
	src := &stubSource{rules: []pg.Rule{{
		UID: "stateful-1", Name: "Stateful", SourceYAML: statefulYAML,
	}}}
	hub := NewHub(src, telemetry.NewCounters())
	if _, err := hub.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	rs := hub.Current()
	if len(rs.GetRules()) != 1 {
		t.Fatalf("rule count = %d", len(rs.GetRules()))
	}
	er := rs.GetRules()[0]
	if er.GetAstVersion() != astVersionStateful {
		t.Errorf("ast_version = %d, want %d", er.GetAstVersion(), astVersionStateful)
	}
	if er.GetStateWindowSecs() != 60 {
		t.Errorf("state_window_secs = %d, want 60", er.GetStateWindowSecs())
	}
	if er.GetStateCap() == 0 {
		t.Errorf("state_cap = 0, want non-zero")
	}
}

func TestHub_FiltersServerOnly(t *testing.T) {
	src := &stubSource{rules: []pg.Rule{
		{UID: "edge-rule", SourceYAML: sampleYAML},
		{UID: "server-only", SourceYAML: serverOnlyYAML},
	}}
	hub := NewHub(src, telemetry.NewCounters())
	skipped, err := hub.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (server-only)", skipped)
	}
	rs := hub.Current()
	if len(rs.GetRules()) != 1 {
		t.Fatalf("wire rule count = %d, want 1 (only edge-eligible)", len(rs.GetRules()))
	}
	if rs.GetRules()[0].GetRuleId() != "edge-rule" {
		t.Errorf("wrong rule kept on the wire: %q", rs.GetRules()[0].GetRuleId())
	}
}

// silence unused-import warnings if a future refactor strips this file.
var _ = pb.OcsfClassId(0)
