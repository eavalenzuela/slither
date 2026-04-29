//go:build linux

package respond

import (
	"context"
	"os"
	"strings"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestParseTargetPID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int
		wantErr string
	}{
		{"1234", 1234, ""},
		{"  4242  ", 4242, ""},
		{"", 0, "required"},
		{"abc", 0, "not a pid"},
		{"0", 0, "must be > 0"},
		{"-5", 0, "must be > 0"},
	}
	for _, c := range cases {
		got, err := parseTargetPID(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("parseTargetPID(%q) err = %v, want nil", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("parseTargetPID(%q) = %d, want %d", c.in, got, c.want)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("parseTargetPID(%q) err = %v, want substring %q", c.in, err, c.wantErr)
		}
	}
}

func TestRefuseDangerousPID_PID1(t *testing.T) {
	t.Parallel()
	if err := refuseDangerousPID(1); err == nil || !strings.Contains(err.Error(), "pid 1") {
		t.Fatalf("refuseDangerousPID(1) = %v, want pid-1 refusal", err)
	}
}

func TestRefuseDangerousPID_AgentSelf(t *testing.T) {
	t.Parallel()
	if err := refuseDangerousPID(os.Getpid()); err == nil || !strings.Contains(err.Error(), "own PID") {
		t.Fatalf("refuseDangerousPID(self) = %v, want own-PID refusal", err)
	}
}

func TestRefuseDangerousPID_AgentAncestor(t *testing.T) {
	t.Parallel()
	// Agent's parent is reachable through /proc — walking up from
	// self.PPid hits something that is by definition an ancestor.
	parent := os.Getppid()
	if parent <= 1 {
		t.Skip("agent ppid is 1 or 0; ancestor check skipped")
	}
	err := refuseDangerousPID(parent)
	if err == nil {
		t.Fatalf("refuseDangerousPID(ppid=%d) = nil, want refusal", parent)
	}
	if !strings.Contains(err.Error(), "ancestor") {
		t.Errorf("err = %v, want ancestor refusal", err)
	}
}

func TestPIDIsAgentAncestor_NonAncestor(t *testing.T) {
	t.Parallel()
	// Spawn a sibling and confirm the ancestor walk doesn't claim
	// it. Use exec for a real child, not just os.Process.
	cmd := mustSpawnSleep(t, "30s")
	defer mustReap(t, cmd)
	got, err := pidIsAgentAncestor(cmd.Process.Pid, os.Getpid())
	if err != nil {
		t.Fatalf("pidIsAgentAncestor: %v", err)
	}
	if got {
		t.Errorf("sibling pid %d reported as agent ancestor", cmd.Process.Pid)
	}
}

func TestKillHandler_RefusesPID1ViaWire(t *testing.T) {
	t.Parallel()
	h := KillProcessHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "1"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Errorf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "pid 1") {
		t.Errorf("detail = %q, want pid-1 refusal", detail)
	}
}

func TestKillHandler_RefusesGarbageTarget(t *testing.T) {
	t.Parallel()
	h := KillProcessHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "abc"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Errorf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "not a pid") {
		t.Errorf("detail = %q, want parse error", detail)
	}
}

func TestCollectDescendants_ChildAppears(t *testing.T) {
	t.Parallel()
	cmd := mustSpawnSleep(t, "30s")
	defer mustReap(t, cmd)

	tree, err := collectDescendants(os.Getpid(), 256)
	if err != nil {
		t.Fatalf("collectDescendants: %v", err)
	}
	found := false
	for _, p := range tree {
		if p == cmd.Process.Pid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("child pid %d not in tree %v", cmd.Process.Pid, tree)
	}
	if tree[0] != os.Getpid() {
		t.Errorf("tree[0] = %d, want self %d", tree[0], os.Getpid())
	}
}

func TestCollectDescendants_RespectsCap(t *testing.T) {
	t.Parallel()
	// Spawn a child so BFS has something to enqueue past root.
	// cap=1 lets root land but trips on the first descendant.
	cmd := mustSpawnSleep(t, "30s")
	defer mustReap(t, cmd)
	_, err := collectDescendants(os.Getpid(), 1)
	if err == nil {
		t.Fatal("expected overflow error at cap=1 with one child")
	}
	if !strings.Contains(err.Error(), "exceeds cap") {
		t.Errorf("err = %v, want exceeds-cap error", err)
	}
}

// TestKillIntegration_TerminatesSleepChild is the privileged-ish
// kill smoke. Spawns a long-running sleep, fires KillProcessHandler
// against its PID, asserts the child exits within the grace+kill
// window. Uses the agent's own parent of `sleep` so no special
// privileges beyond signal-to-own-child are required.
func TestKillIntegration_TerminatesSleepChild(t *testing.T) {
	t.Parallel()
	cmd := mustSpawnSleep(t, "120s")
	pid := cmd.Process.Pid

	h := KillProcessHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: itoa(pid)})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("kill status = %s, detail = %q, want DONE", status, detail)
	}

	// Reap. Since the agent's the parent, Wait reports the exit.
	_ = cmd.Wait()
	if pidAlive(pid) {
		t.Errorf("pid %d still alive after kill handler returned DONE", pid)
	}
}

func TestKillTreeIntegration_TerminatesGrandchild(t *testing.T) {
	t.Parallel()
	// Spawn a sh that spawns a sleep WITHOUT `exec` — `exec sleep`
	// would replace the sh in place, defeating the tree depth this
	// test exercises. With a plain invocation, sh stays alive as the
	// parent and sleep is a real grandchild.
	parent := mustSpawnSh(t, "sleep 120 & wait")
	parentPID := parent.Process.Pid

	// Wait for the grandchild to appear so the tree walk sees it.
	// /proc/<sh>/task/<tid>/children lists the sleep within a few ms.
	waitForChild(t, parentPID)

	h := KillTreeHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: itoa(parentPID)})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("tree kill status = %s, detail = %q, want DONE", status, detail)
	}
	_ = parent.Wait()
	if pidAlive(parentPID) {
		t.Errorf("parent pid %d still alive", parentPID)
	}
}
