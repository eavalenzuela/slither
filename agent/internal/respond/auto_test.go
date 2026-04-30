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
	ar.OnFinding(context.Background(), intent, fakeProcessEvent("/bin/sh", "curl http://x"), finding, ruleast.CategoryProcessCreation)

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
	ar.OnFinding(context.Background(), intent, ev, finding, ruleast.CategoryProcessCreation)

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
	ar.OnFinding(context.Background(), intent, ev, finding, ruleast.CategoryProcessCreation)

	if finding.AutoResponseExecuted {
		t.Error("Executed = true with unresolvable target")
	}
	if !finding.AutoResponseWouldHaveExecuted {
		t.Error("WouldHaveExecuted = false with unresolvable target")
	}
}

func TestAutoResponder_NilSafe(t *testing.T) {
	t.Parallel()
	var ar *AutoResponder
	finding := &ocsf.DetectionFinding{}
	// Nil receiver should not panic + should leave finding untouched.
	ar.OnFinding(context.Background(), &ruleast.ResponseIntent{}, nil, finding, ruleast.CategoryProcessCreation)
	if finding.AutoResponseAction != "" || finding.AutoResponseExecuted || finding.AutoResponseWouldHaveExecuted {
		t.Errorf("nil responder mutated finding: %+v", finding)
	}
}
