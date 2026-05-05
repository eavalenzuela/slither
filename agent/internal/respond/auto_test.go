package respond

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// fakeProcessEvent builds a minimal *ocsf.ProcessActivity that the
// process-creation accessor table will resolve fields against.
func fakeProcessEvent(image, cmdline string) *ocsf.ProcessActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "auto-ev"},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Time:       ocsf.TimeOCSF(ts),
		Process: ocsf.Process{
			PID:     4242,
			Name:    "sh",
			Cmdline: cmdline,
			File:    &ocsf.File{Path: image, Name: "sh"},
		},
	}
}

func TestPolicyAllows_NilPolicyDeniesAll(t *testing.T) {
	t.Parallel()
	for _, a := range []ruleast.ResponseAction{
		ruleast.ResponseActionKillProcess,
		ruleast.ResponseActionKillProcessTree,
		ruleast.ResponseActionQuarantineFile,
		ruleast.ResponseActionIsolateHost,
		ruleast.ResponseActionUnisolateHost,
		ruleast.ResponseActionCollectArtifacts,
	} {
		if policyAllows(nil, a) {
			t.Errorf("nil policy should deny %s", a)
		}
	}
}

func TestPolicyAllows_UnisolateInheritsIsolate(t *testing.T) {
	t.Parallel()
	p := &pb.HostPolicy{AllowIsolate: true}
	if !policyAllows(p, ruleast.ResponseActionIsolateHost) {
		t.Error("isolate not permitted under AllowIsolate=true")
	}
	if !policyAllows(p, ruleast.ResponseActionUnisolateHost) {
		t.Error("unisolate not permitted under AllowIsolate=true (should inherit)")
	}
}

func TestPolicyAllows_PerActionFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		policy *pb.HostPolicy
		action ruleast.ResponseAction
		want   bool
	}{
		{"kill on", &pb.HostPolicy{AllowKillProcess: true}, ruleast.ResponseActionKillProcess, true},
		{"kill off", &pb.HostPolicy{}, ruleast.ResponseActionKillProcess, false},
		{"tree on", &pb.HostPolicy{AllowKillTree: true}, ruleast.ResponseActionKillProcessTree, true},
		{"quarantine on", &pb.HostPolicy{AllowQuarantine: true}, ruleast.ResponseActionQuarantineFile, true},
		{"collect on", &pb.HostPolicy{AllowCollect: true}, ruleast.ResponseActionCollectArtifacts, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := policyAllows(c.policy, c.action); got != c.want {
				t.Errorf("policyAllows = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAutoResponder_DetectOnlyStampsWouldHaveExecuted(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	ar := NewAutoResponder(exec, func() *pb.HostPolicy { return nil })

	finding := &ocsf.DetectionFinding{}
	intent := &ruleast.ResponseIntent{
		Action:      ruleast.ResponseActionKillProcess,
		TargetField: "Image",
	}
	ar.OnFinding(context.Background(), intent, false, fakeProcessEvent("/bin/sh", "curl http://x"), finding, ruleast.CategoryProcessCreation)

	if finding.AutoResponseExecuted {
		t.Error("AutoResponseExecuted = true on detect-only host")
	}
	if !finding.AutoResponseWouldHaveExecuted {
		t.Error("AutoResponseWouldHaveExecuted = false on detect-only host")
	}
	if finding.AutoResponseAction != "kill_process" {
		t.Errorf("AutoResponseAction = %q, want kill_process", finding.AutoResponseAction)
	}
	// Executor should not have been invoked.
	select {
	case r := <-results:
		t.Errorf("unexpected result %+v on detect-only host", r)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAutoResponder_PermissivePolicySubmitsToExecutor(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	// Stub handler: capture target + return DONE so the synthetic
	// FAILED-on-queue-full path doesn't interfere with the assert.
	captured := make(chan string, 1)
	exec.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			captured <- req.GetTarget()
			return pb.ResponseStatus_RESPONSE_STATUS_DONE, "ok", nil
		})

	policy := func() *pb.HostPolicy { return &pb.HostPolicy{AllowKillProcess: true} }
	ar := NewAutoResponder(exec, policy)

	finding := &ocsf.DetectionFinding{}
	intent := &ruleast.ResponseIntent{
		Action:      ruleast.ResponseActionKillProcess,
		TargetField: "Image",
	}
	ev := fakeProcessEvent("/usr/bin/curl", "curl http://x")
	ar.OnFinding(context.Background(), intent, false, ev, finding, ruleast.CategoryProcessCreation)

	if !finding.AutoResponseExecuted {
		t.Error("AutoResponseExecuted = false on permissive host")
	}
	if finding.AutoResponseWouldHaveExecuted {
		t.Error("AutoResponseWouldHaveExecuted = true alongside Executed")
	}

	select {
	case got := <-captured:
		if got != "/usr/bin/curl" {
			t.Errorf("target = %q, want /usr/bin/curl", got)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was never invoked")
	}
}

func TestAutoResponder_UnresolvableFieldStampsWouldHaveExecuted(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	policy := func() *pb.HostPolicy { return &pb.HostPolicy{AllowKillProcess: true} }
	ar := NewAutoResponder(exec, policy)

	finding := &ocsf.DetectionFinding{}
	intent := &ruleast.ResponseIntent{
		Action:      ruleast.ResponseActionKillProcess,
		TargetField: "FieldThatDoesNotExist",
	}
	ev := fakeProcessEvent("/bin/sh", "curl")
	ar.OnFinding(context.Background(), intent, false, ev, finding, ruleast.CategoryProcessCreation)

	if finding.AutoResponseExecuted {
		t.Error("Executed = true with unresolvable target")
	}
	if !finding.AutoResponseWouldHaveExecuted {
		t.Error("WouldHaveExecuted = false with unresolvable target")
	}
}

// Phase 5 #88b: duplicate firings of the same rule against the same
// target inside the dedupe window must not produce a second executor
// submission. The finding still emits both times (it's an honest
// observation), but the second observation leaves Executed +
// WouldHaveExecuted both false — there's nothing to claim, the first
// fire owns the action.
func TestAutoResponder_DedupesDuplicateFiresWithinWindow(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	captured := make(chan string, 4)
	exec.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			captured <- req.GetTarget()
			return pb.ResponseStatus_RESPONSE_STATUS_DONE, "ok", nil
		})

	policy := func() *pb.HostPolicy { return &pb.HostPolicy{AllowKillProcess: true} }
	ar := NewAutoResponder(exec, policy)

	intent := &ruleast.ResponseIntent{
		Action:      ruleast.ResponseActionKillProcess,
		TargetField: "Image",
	}
	ev := fakeProcessEvent("/usr/bin/curl", "curl http://x")

	// First fire — submits.
	first := &ocsf.DetectionFinding{RuleInfo: ocsf.Rule{UID: "rule-uid-A"}}
	ar.OnFinding(context.Background(), intent, false, ev, first, ruleast.CategoryProcessCreation)
	if !first.AutoResponseExecuted {
		t.Error("first finding: AutoResponseExecuted = false, want true")
	}

	// Second fire on the same rule + target — should be deduped.
	second := &ocsf.DetectionFinding{RuleInfo: ocsf.Rule{UID: "rule-uid-A"}}
	ar.OnFinding(context.Background(), intent, false, ev, second, ruleast.CategoryProcessCreation)
	if second.AutoResponseExecuted {
		t.Error("dedupe: second AutoResponseExecuted = true, want false")
	}
	if second.AutoResponseWouldHaveExecuted {
		t.Error("dedupe: second AutoResponseWouldHaveExecuted = true, want false")
	}

	// Different rule_uid should NOT dedupe.
	third := &ocsf.DetectionFinding{RuleInfo: ocsf.Rule{UID: "rule-uid-B"}}
	ar.OnFinding(context.Background(), intent, false, ev, third, ruleast.CategoryProcessCreation)
	if !third.AutoResponseExecuted {
		t.Error("different rule_uid: AutoResponseExecuted = false, want true (no dedupe)")
	}

	// Drain — exactly two handler invocations: first + third.
	got := 0
	for {
		select {
		case <-captured:
			got++
		case <-time.After(200 * time.Millisecond):
			if got != 2 {
				t.Errorf("handler invocations = %d, want 2", got)
			}
			return
		}
	}
}

// Outside the dedupe window the same (rule_uid, target) submits again.
// Use the AutoResponder's now hook to simulate clock advancement
// without sleeping.
func TestAutoResponder_DedupeExpiresAfterWindow(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	exec.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, _ *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			return pb.ResponseStatus_RESPONSE_STATUS_DONE, "ok", nil
		})

	policy := func() *pb.HostPolicy { return &pb.HostPolicy{AllowKillProcess: true} }
	ar := NewAutoResponder(exec, policy)

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	clock := t0
	ar.now = func() time.Time { return clock }

	intent := &ruleast.ResponseIntent{
		Action:      ruleast.ResponseActionKillProcess,
		TargetField: "Image",
	}
	ev := fakeProcessEvent("/usr/bin/curl", "curl http://x")

	first := &ocsf.DetectionFinding{RuleInfo: ocsf.Rule{UID: "rule-uid-A"}}
	ar.OnFinding(context.Background(), intent, false, ev, first, ruleast.CategoryProcessCreation)
	if !first.AutoResponseExecuted {
		t.Fatal("first fire didn't execute")
	}

	// Advance past the dedupe window.
	clock = t0.Add(dedupeWindow + 100*time.Millisecond)

	second := &ocsf.DetectionFinding{RuleInfo: ocsf.Rule{UID: "rule-uid-A"}}
	ar.OnFinding(context.Background(), intent, false, ev, second, ruleast.CategoryProcessCreation)
	if !second.AutoResponseExecuted {
		t.Error("post-window fire: AutoResponseExecuted = false, dedupe should have expired")
	}
}

func TestAutoResponder_NilSafe(t *testing.T) {
	t.Parallel()
	var ar *AutoResponder
	finding := &ocsf.DetectionFinding{}
	// Nil receiver should not panic + should leave finding untouched.
	ar.OnFinding(context.Background(), &ruleast.ResponseIntent{}, false, nil, finding, ruleast.CategoryProcessCreation)
	if finding.AutoResponseAction != "" || finding.AutoResponseExecuted || finding.AutoResponseWouldHaveExecuted {
		t.Errorf("nil responder mutated finding: %+v", finding)
	}
}

// --- Phase 6 #111 snapshot dispatch tests -------------------------------

// stubSnapshotDispatcher satisfies SnapshotDispatcher for tests. The
// fanout returns one preconfigured set of provider channels per
// DispatchSnapshot call; nilOnNoProviders mirrors the real manager's
// "no provider declared" sentinel.
type stubSnapshotDispatcher struct {
	providers     []string
	feedChunks    [][]byte // chunks each provider streams (one entry per provider)
	failProviders map[string]bool
	noProviders   bool
}

func (s *stubSnapshotDispatcher) DispatchSnapshot(_ context.Context, req *pb.SnapshotRequest) ([]SnapshotProviderReplies, error) {
	if s.noProviders {
		return nil, ErrNoSnapshotProvider
	}
	out := make([]SnapshotProviderReplies, 0, len(s.providers))
	for i, name := range s.providers {
		ch := make(chan *pb.ExtensionToAgent, 4)
		var chunkBytes []byte
		if i < len(s.feedChunks) {
			chunkBytes = s.feedChunks[i]
		}
		if len(chunkBytes) > 0 {
			// Empty Sha256 → responder skips verify. Tests cover the
			// happy path without re-implementing the rolling hash.
			ch <- &pb.ExtensionToAgent{
				Payload: &pb.ExtensionToAgent_SnapshotChunk{
					SnapshotChunk: &pb.SnapshotChunk{
						SnapshotId: req.GetSnapshotId(),
						Bytes:      chunkBytes,
					},
				},
			}
		}
		errStr := ""
		if s.failProviders[name] {
			errStr = "stub-failure"
		}
		ch <- &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_SnapshotComplete{
				SnapshotComplete: &pb.SnapshotComplete{
					SnapshotId: req.GetSnapshotId(),
					Manifest:   "stub-manifest",
					Error:      errStr,
				},
			},
		}
		close(ch)
		out = append(out, SnapshotProviderReplies{ExtensionName: name, Replies: ch})
	}
	return out, nil
}

func TestAutoResponder_SnapshotNoProviders(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	exec := New(Options{Results: results, Telem: telemetry.NewCounters()})
	ar := NewAutoResponder(exec, func() *pb.HostPolicy { return nil })
	ar.SetSnapshotDispatcher(&stubSnapshotDispatcher{noProviders: true}, telemetry.NewCounters())

	finding := &ocsf.DetectionFinding{Finding: ocsf.Finding{UID: "alert-1"}}
	ar.OnFinding(context.Background(), nil, true, fakeProcessEvent("/bin/sh", "x"), finding, ruleast.CategoryProcessCreation)

	if !finding.SnapshotNoProviders {
		t.Error("SnapshotNoProviders = false; want true")
	}
	if finding.SnapshotRequested {
		t.Error("SnapshotRequested = true with no providers")
	}
	select {
	case r := <-results:
		t.Errorf("unexpected result %+v on no-provider path", r)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAutoResponder_SnapshotFanoutSubmits(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	telem := telemetry.NewCounters()
	exec := New(Options{Results: results, Telem: telem})
	ar := NewAutoResponder(exec, func() *pb.HostPolicy { return nil })
	ar.SetSnapshotDispatcher(&stubSnapshotDispatcher{
		providers:  []string{"ext-a", "ext-b"},
		feedChunks: [][]byte{[]byte("blob-A"), []byte("blob-B")},
	}, telem)

	finding := &ocsf.DetectionFinding{Finding: ocsf.Finding{UID: "alert-1"}, RuleInfo: ocsf.Rule{UID: "rule-1"}}
	ar.OnFinding(context.Background(), nil, true, fakeProcessEvent("/bin/sh", "x"), finding, ruleast.CategoryProcessCreation)

	if !finding.SnapshotRequested {
		t.Error("SnapshotRequested = false")
	}
	if finding.SnapshotNoProviders {
		t.Error("SnapshotNoProviders = true on success path")
	}

	got := drainResults(t, results, 2, 2*time.Second)
	gotByExt := map[string]*pb.ResponseResult{}
	for _, r := range got {
		gotByExt[r.GetSnapshotExtensionName()] = r
	}
	for _, ext := range []string{"ext-a", "ext-b"} {
		r, ok := gotByExt[ext]
		if !ok {
			t.Fatalf("no ResponseResult for ext %q", ext)
		}
		if r.GetAction() != pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS {
			t.Errorf("ext %q action = %v, want COLLECT_ARTIFACTS", ext, r.GetAction())
		}
		if r.GetSnapshotAlertId() != "alert-1" {
			t.Errorf("ext %q SnapshotAlertId = %q", ext, r.GetSnapshotAlertId())
		}
		if r.GetRuleUid() != "rule-1" {
			t.Errorf("ext %q RuleUid = %q", ext, r.GetRuleUid())
		}
		if len(r.GetResultBlob()) == 0 {
			t.Errorf("ext %q result_blob empty", ext)
		}
	}

	snap := telem.Snapshot()
	if snap.ExtSnapshotsCompleted != 2 {
		t.Errorf("ExtSnapshotsCompleted = %d, want 2", snap.ExtSnapshotsCompleted)
	}
}

func TestAutoResponder_SnapshotFailedTerminalCounts(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	telem := telemetry.NewCounters()
	exec := New(Options{Results: results, Telem: telem})
	ar := NewAutoResponder(exec, func() *pb.HostPolicy { return nil })
	ar.SetSnapshotDispatcher(&stubSnapshotDispatcher{
		providers:     []string{"ext-bad"},
		feedChunks:    [][]byte{[]byte("ignored")},
		failProviders: map[string]bool{"ext-bad": true},
	}, telem)

	finding := &ocsf.DetectionFinding{Finding: ocsf.Finding{UID: "alert-2"}, RuleInfo: ocsf.Rule{UID: "rule-2"}}
	ar.OnFinding(context.Background(), nil, true, fakeProcessEvent("/bin/sh", "x"), finding, ruleast.CategoryProcessCreation)

	// Wait for the goroutine.
	deadline := time.After(2 * time.Second)
	for telem.Snapshot().ExtSnapshotsFailed == 0 {
		select {
		case <-deadline:
			t.Fatal("ExtSnapshotsFailed never ticked")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	select {
	case r := <-results:
		t.Errorf("unexpected result %+v on failed-terminal path", r)
	case <-time.After(50 * time.Millisecond):
	}
}

func drainResults(t *testing.T, ch <-chan *pb.ResponseResult, n int, d time.Duration) []*pb.ResponseResult {
	t.Helper()
	out := make([]*pb.ResponseResult, 0, n)
	deadline := time.After(d)
	for len(out) < n {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-deadline:
			t.Fatalf("drainResults: got %d, want %d before %s", len(out), n, d)
		}
	}
	return out
}
