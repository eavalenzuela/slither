package ruleengine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// recordingHook captures every OnFinding call so tests can assert on
// what the engine routed.
type recordingHook struct {
	mu    sync.Mutex
	calls []hookCall
	// stamp lets tests preset the side-effect on the finding.
	stamp func(f *ocsf.DetectionFinding)
}

type hookCall struct {
	intent   *ruleast.ResponseIntent
	snapshot bool
	trigger  ocsf.Event
	finding  *ocsf.DetectionFinding
	cat      ruleast.Category
}

func (h *recordingHook) OnFinding(_ context.Context, intent *ruleast.ResponseIntent, snapshot bool, trigger ocsf.Event, finding *ocsf.DetectionFinding, cat ruleast.Category) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, hookCall{intent: intent, snapshot: snapshot, trigger: trigger, finding: finding, cat: cat})
	if h.stamp != nil {
		h.stamp(finding)
	}
}

func (h *recordingHook) snapshot() []hookCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]hookCall, len(h.calls))
	copy(out, h.calls)
	return out
}

const responseRuleSigma = `title: curl with auto-kill response
id: 33333333-3333-4333-8333-333333333333
description: rule that auto-kills the spawning shell
level: high
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    Image|endswith: /sh
    CommandLine|contains: curl
  condition: sel
slither:
  response:
    action: kill_process
    target_field: Image
    immediate: true
`

const noResponseRuleSigma = `title: plain curl in shell
id: 44444444-4444-4444-8444-444444444444
description: detect-only rule, no response block
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    Image|endswith: /sh
    CommandLine|contains: curl
  condition: sel
`

func TestAutoResponse_HookFiresWithIntent(t *testing.T) {
	t.Parallel()
	art, _, _, err := ruleast.Compile([]byte(responseRuleSigma))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules, err := CompileArtefacts([]*ruleast.EdgeArtefact{art}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileArtefacts: %v", err)
	}
	hook := &recordingHook{
		stamp: func(f *ocsf.DetectionFinding) { f.AutoResponseExecuted = true },
	}

	eng := New(rules, telemetry.NewCounters())
	eng.SetAutoRespondHook(hook)

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "curl http://example")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil && err != context.DeadlineExceeded {
		t.Fatalf("Run: %v", err)
	}

	calls := hook.snapshot()
	if len(calls) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.intent == nil || c.intent.Action != ruleast.ResponseActionKillProcess {
		t.Errorf("intent = %+v, want kill_process", c.intent)
	}
	if c.intent.TargetField != "Image" {
		t.Errorf("target_field = %q, want Image", c.intent.TargetField)
	}
	if c.cat != ruleast.CategoryProcessCreation {
		t.Errorf("category = %q, want process_creation", c.cat)
	}
	if !c.finding.AutoResponseExecuted {
		t.Error("hook did not stamp AutoResponseExecuted on the finding")
	}
}

func TestAutoResponse_NoHookWithoutIntent(t *testing.T) {
	t.Parallel()
	art, _, _, err := ruleast.Compile([]byte(noResponseRuleSigma))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules, err := CompileArtefacts([]*ruleast.EdgeArtefact{art}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileArtefacts: %v", err)
	}
	hook := &recordingHook{}
	eng := New(rules, telemetry.NewCounters())
	eng.SetAutoRespondHook(hook)

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "curl http://example")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = eng.Run(ctx, in)

	if got := len(hook.snapshot()); got != 0 {
		t.Errorf("hook fired %d times for rule without response intent, want 0", got)
	}
}

func TestAutoResponse_HookSkippedWhenNil(t *testing.T) {
	t.Parallel()
	// Rule has an intent, but engine has no hook installed → finding
	// ships with auto-response fields untouched.
	art, _, _, err := ruleast.Compile([]byte(responseRuleSigma))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules, err := CompileArtefacts([]*ruleast.EdgeArtefact{art}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileArtefacts: %v", err)
	}
	eng := New(rules, telemetry.NewCounters())
	// no SetAutoRespondHook call

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "curl http://example")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = eng.Run(ctx, in) }()

	gotFinding := false
	deadline := time.After(time.Second)
	for !gotFinding {
		select {
		case ev := <-eng.Output():
			if f, ok := ev.(*ocsf.DetectionFinding); ok {
				if f.AutoResponseExecuted || f.AutoResponseWouldHaveExecuted || f.AutoResponseAction != "" {
					t.Errorf("auto-response fields should be empty without hook, got %+v", f)
				}
				gotFinding = true
			}
		case <-deadline:
			t.Fatal("did not receive finding before deadline")
		}
	}
}

func TestCompileArtefacts_PreservesIntent(t *testing.T) {
	t.Parallel()
	art, _, _, err := ruleast.Compile([]byte(responseRuleSigma))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rules, err := CompileArtefacts([]*ruleast.EdgeArtefact{art}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileArtefacts: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	scr, ok := rules[0].(*sigmaCompiledRule)
	if !ok {
		t.Fatalf("compiled rule is %T, want *sigmaCompiledRule", rules[0])
	}
	if scr.response == nil {
		t.Fatal("intent dropped during CompileArtefacts")
	}
	if scr.response.Action != ruleast.ResponseActionKillProcess {
		t.Errorf("action = %q, want kill_process", scr.response.Action)
	}
	if scr.response.TargetField != "Image" {
		t.Errorf("target_field = %q, want Image", scr.response.TargetField)
	}
}
