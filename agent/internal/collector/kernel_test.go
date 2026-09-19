//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

func TestDecodeKernelKind(t *testing.T) {
	cases := map[uint32]pipeline.RawKernelKind{
		0: pipeline.KernelUnknown,
		1: pipeline.KernelModuleLoad,
		2: pipeline.KernelModuleUnload,
		3: pipeline.KernelModuleLoadRejected,
		4: pipeline.KernelBPFProgLoad,
		5: pipeline.KernelProbeAttach,
		9: pipeline.KernelUnknown,
	}
	for raw, want := range cases {
		if got := decodeKernelKind(raw); got != want {
			t.Errorf("decodeKernelKind(%d) = %d, want %d", raw, got, want)
		}
	}
}

func testKernelCollector() *kernelCollector {
	return &kernelCollector{
		out:        make(chan pipeline.RawKernelEvent, 1),
		telem:      telemetry.NewCounters(),
		kprobeType: 8,
		uprobeType: 9,
	}
}

func TestDecodeKernelModuleLoadCarriesTaints(t *testing.T) {
	var r bpfpkg.KernelKernelEvent
	r.Kind, r.Tgid, r.Uid, r.Taints = 1, 4200, 0, 1<<12|1<<13
	fill(r.Name[:], "rootkit")
	fill(r.Comm[:], "insmod")
	ev, ok := testKernelCollector().decode(r)
	if !ok {
		t.Fatal("module_load must decode")
	}
	if ev.Kind != pipeline.KernelModuleLoad || ev.PID != 4200 || ev.Name != "rootkit" || ev.Taints != 1<<12|1<<13 || ev.SystemCall != "init_module" {
		t.Errorf("decoded %+v", ev)
	}
}

func TestDecodeKernelRejectedLoadNegatesErrno(t *testing.T) {
	var r bpfpkg.KernelKernelEvent
	r.Kind, r.Result = 3, -129 // EKEYREJECTED
	ev, ok := testKernelCollector().decode(r)
	if !ok || ev.Kind != pipeline.KernelModuleLoadRejected || ev.Errno != 129 {
		t.Errorf("decoded %+v ok=%v", ev, ok)
	}
}

func TestDecodeKernelBPFProgLoad(t *testing.T) {
	var r bpfpkg.KernelKernelEvent
	r.Kind, r.AttrType = 4, 2 // kprobe program
	fill(r.Name[:], "hook_execve")
	ev, ok := testKernelCollector().decode(r)
	if !ok || ev.Kind != pipeline.KernelBPFProgLoad || ev.ProgType != 2 || ev.Name != "hook_execve" || ev.SystemCall != "bpf" {
		t.Errorf("decoded %+v ok=%v", ev, ok)
	}
}

// TestDecodeKernelProbeAttachClassifiesPMU — the BPF side reports every
// dynamic-PMU perf_event_open; only the kprobe and uprobe PMU ids
// become events, and the retprobe bit + offset ride through.
func TestDecodeKernelProbeAttachClassifiesPMU(t *testing.T) {
	k := testKernelCollector()

	var r bpfpkg.KernelKernelEvent
	r.Kind, r.AttrType, r.Config, r.Config2 = 5, 8, 1, 0
	fill(r.Target[:], "sys_execve")
	ev, ok := k.decode(r)
	if !ok || ev.Probe != "kprobe" || !ev.Retprobe || ev.Name != "sys_execve" || ev.SystemCall != "perf_event_open" {
		t.Errorf("kretprobe decoded %+v ok=%v", ev, ok)
	}

	r.AttrType, r.Config, r.Config2 = 9, 0, 0x1234
	fill(r.Target[:], "/usr/lib/libssl.so.3")
	ev, ok = k.decode(r)
	if !ok || ev.Probe != "uprobe" || ev.Retprobe || ev.Name != "/usr/lib/libssl.so.3" || ev.Offset != 0x1234 {
		t.Errorf("uprobe decoded %+v ok=%v", ev, ok)
	}

	r.AttrType = 20 // some other dynamic PMU (cpu, uncore, intel_pt)
	if _, ok = k.decode(r); ok {
		t.Error("a non-probe dynamic PMU must be dropped")
	}

	k.kprobeType, k.uprobeType = 0, 0 // PMUs absent on this kernel
	r.AttrType = 8
	if _, ok = k.decode(r); ok {
		t.Error("with no kprobe PMU nothing may classify as a kprobe")
	}
}

func TestReadPMUType(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "type")
	if err := os.WriteFile(p, []byte("8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPMUType(p); got != 8 {
		t.Errorf("readPMUType = %d, want 8", got)
	}
	if got := readPMUType(filepath.Join(dir, "missing")); got != 0 {
		t.Errorf("missing file should read as 0, got %d", got)
	}
	if err := os.WriteFile(p, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPMUType(p); got != 0 {
		t.Errorf("malformed file should read as 0, got %d", got)
	}
}
