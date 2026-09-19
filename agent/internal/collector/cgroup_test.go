//go:build linux

package collector

import (
	"testing"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

func TestDecodeCgroupEvent(t *testing.T) {
	var r bpfpkg.CgroupCgroupEvent
	r.Kind, r.Pid, r.Tgid, r.Uid, r.Root, r.Id = 1, 4242, 4200, 0, 0, 155
	fill(r.Path[:], "/system.slice/docker-abc.scope")
	fill(r.Comm[:], "runc")
	ev := decodeCgroupEvent(r)
	if ev.Kind != pipeline.CgroupMkdir || ev.PID != 4200 || ev.Root != 0 || ev.ID != 155 || ev.Path != "/system.slice/docker-abc.scope" || ev.Comm != "runc" {
		t.Errorf("decoded %+v", ev)
	}
	r.Kind = 2
	if got := decodeCgroupEvent(r).Kind; got != pipeline.CgroupRmdir {
		t.Errorf("kind 2 → %d", got)
	}
	r.Kind = 7
	if got := decodeCgroupEvent(r).Kind; got != pipeline.CgroupUnknown {
		t.Errorf("kind 7 → %d", got)
	}
}

// TestDecodeProcessEventCarriesCgroupID — the cgroup id BPF stamps on
// process records must reach the raw event untouched.
func TestDecodeProcessEventCarriesCgroupID(t *testing.T) {
	var r bpfpkg.ProcessProcessEvent
	r.Kind, r.Pid, r.CgroupId = 1, 10, 155
	if got := decodeProcessEvent(r).CgroupID; got != 155 {
		t.Errorf("CgroupID = %d, want 155", got)
	}
}
