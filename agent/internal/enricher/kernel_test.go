package enricher

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func TestKernelActivityIDMapping(t *testing.T) {
	cases := map[pipeline.RawKernelKind]ocsf.KernelActivityID{
		pipeline.KernelModuleLoad:         ocsf.KernelActivityCreate,
		pipeline.KernelModuleLoadRejected: ocsf.KernelActivityCreate,
		pipeline.KernelModuleUnload:       ocsf.KernelActivityDelete,
		pipeline.KernelBPFProgLoad:        ocsf.KernelActivityInvoke,
		pipeline.KernelProbeAttach:        ocsf.KernelActivityInvoke,
		pipeline.KernelUnknown:            ocsf.KernelActivityOther,
	}
	for k, want := range cases {
		if got := kernelActivityID(k); got != want {
			t.Errorf("kernelActivityID(%v) = %d, want %d", k, got, want)
		}
	}
}

func TestTaintNames(t *testing.T) {
	if got := taintNames(0); got != nil {
		t.Errorf("no taints → %v", got)
	}
	got := taintNames(1<<0 | 1<<12 | 1<<13)
	want := []string{"proprietary_module", "out_of_tree", "unsigned_module"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("taintNames = %v, want %v", got, want)
	}
	if got := taintNames(1 << 30); !reflect.DeepEqual(got, []string{"taint_30"}) {
		t.Errorf("unknown bit → %v", got)
	}
}

func TestBPFProgTypeAndErrnoNames(t *testing.T) {
	if bpfProgTypeName(2) != "kprobe" || bpfProgTypeName(5) != "tracepoint" || bpfProgTypeName(29) != "lsm" || bpfProgTypeName(99) != "prog_type_99" {
		t.Error("bpfProgTypeName table drifted")
	}
	if errnoName(129) != "EKEYREJECTED" || errnoName(1) != "EPERM" || errnoName(74) != "EBADMSG" || errnoName(200) != "E200" {
		t.Error("errnoName table drifted")
	}
}

func TestHandleKernelModuleLoadBuildsValidOCSF(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{pid: 500, uid: 0, comm: "insmod", exe: "/usr/sbin/insmod", cmdline: "insmod /tmp/rk.ko"})

	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelModuleLoad, PID: 500, UID: 0, Name: "rk",
		Taints: 1<<12 | 1<<13, SystemCall: "init_module", Comm: "insmod",
		Timestamp: time.Unix(100, 0),
	})
	k := (<-e.out).(*ocsf.KernelActivity)
	if err := k.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if k.TypeUID != 100301 || k.Metadata.EventCode != "module_load" || k.Metadata.LogName != "kernel" {
		t.Errorf("type/event_code = %d/%q", k.TypeUID, k.Metadata.EventCode)
	}
	if k.Kernel.Name != "rk" || k.Kernel.Type != "Module" || k.Kernel.SystemCall != "init_module" {
		t.Errorf("kernel = %+v", k.Kernel)
	}
	if !reflect.DeepEqual(k.Kernel.Taints, []string{"out_of_tree", "unsigned_module"}) {
		t.Errorf("taints = %v", k.Kernel.Taints)
	}
	if k.Status != "Success" || k.StatusID != 1 {
		t.Errorf("status = %q/%d", k.Status, k.StatusID)
	}
	if k.Actor.Process.Cmdline != "insmod /tmp/rk.ko" || k.Actor.User.Name != "root" {
		t.Errorf("actor = %+v", k.Actor)
	}
}

func TestHandleKernelRejectedLoadIsFailure(t *testing.T) {
	e := newTestEnricher(t)
	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelModuleLoadRejected, PID: 501, UID: 0, Errno: 129,
		SystemCall: "init_module", Comm: "insmod", Timestamp: time.Unix(100, 0),
	})
	k := (<-e.out).(*ocsf.KernelActivity)
	if err := k.Validate(); err != nil {
		t.Fatalf("Validate (no module name, type must carry it): %v", err)
	}
	if k.Status != "Failure" || k.StatusID != 2 || k.StatusCode != "129" || k.StatusDetail != "EKEYREJECTED" {
		t.Errorf("status = %q/%d/%q/%q", k.Status, k.StatusID, k.StatusCode, k.StatusDetail)
	}
	if k.Metadata.EventCode != "module_load_rejected" || k.Kernel.Type != "Module" || k.ActivityID != ocsf.KernelActivityCreate {
		t.Errorf("event = %+v", k)
	}
	if k.Actor.Process.Name != "insmod" {
		t.Errorf("cache miss should still name the actor from comm: %+v", k.Actor.Process)
	}
}

func TestHandleKernelProbeAndBPF(t *testing.T) {
	e := newTestEnricher(t)
	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelProbeAttach, PID: 600, UID: 0, Name: "/usr/lib/libssl.so.3",
		Probe: "uprobe", Retprobe: true, Offset: 0x1f40, SystemCall: "perf_event_open",
		Comm: "stealer", Timestamp: time.Unix(100, 0),
	})
	k := (<-e.out).(*ocsf.KernelActivity)
	if k.Kernel.Type != "Uretprobe" || k.Kernel.Path != "/usr/lib/libssl.so.3" || k.Kernel.Offset != "0x1f40" || k.ActivityID != ocsf.KernelActivityInvoke {
		t.Errorf("uretprobe = %+v", k.Kernel)
	}

	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelBPFProgLoad, PID: 600, UID: 0, Name: "hook", ProgType: 2,
		SystemCall: "bpf", Comm: "rk", Timestamp: time.Unix(100, 0),
	})
	k = (<-e.out).(*ocsf.KernelActivity)
	if k.Kernel.Type != "BPF Program" || k.Kernel.ProgType != "kprobe" || k.Kernel.Name != "hook" || k.Metadata.EventCode != "bpf_prog_load" {
		t.Errorf("bpf = %+v", k.Kernel)
	}
}

// TestHandleKernelDropsOwnPID — the agent's own BPF loads and probe
// attaches never become events.
func TestHandleKernelDropsOwnPID(t *testing.T) {
	e := newTestEnricher(t)
	e.selfPID = 4242
	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelBPFProgLoad, PID: 4242, Name: "handle_exec", ProgType: 5, Timestamp: time.Unix(1, 0),
	})
	e.handleKernel(context.Background(), pipeline.RawKernelEvent{
		Kind: pipeline.KernelBPFProgLoad, PID: 4243, Name: "other", ProgType: 5, Timestamp: time.Unix(1, 0),
	})
	k := (<-e.out).(*ocsf.KernelActivity)
	if k.Kernel.Name != "other" {
		t.Errorf("self event should have been dropped; got %q", k.Kernel.Name)
	}
	select {
	case ev := <-e.out:
		t.Fatalf("unexpected second event %+v", ev)
	default:
	}
}
