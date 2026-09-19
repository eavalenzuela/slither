//go:build linux && integration

package collector

import (
	"testing"
	"time"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestKernelCollector_BPFProgLoadObserved attaches kernel.bpf.c and then
// loads a second copy of the same object set from this process: every
// program in it goes through bpf(BPF_PROG_LOAD), which the
// sys_enter_bpf hook must report with the program's type and name.
func TestKernelCollector_BPFProgLoadObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawKernelEvent, 1024)
	c := newKernelCollector(out, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	var objs bpfpkg.KernelObjects
	if err := bpfpkg.LoadKernelObjects(&objs, nil); err != nil {
		t.Fatalf("second LoadKernelObjects: %v", err)
	}
	objs.Close()

	ev, ok := waitForEvent(t, out, func(e pipeline.RawKernelEvent) bool {
		return e.Kind == pipeline.KernelBPFProgLoad && e.Name == "handle_bpf"
	}, 3*time.Second)
	if !ok {
		t.Fatal("no bpf_prog_load event for handle_bpf within 3s")
	}
	if ev.ProgType != 5 { // BPF_PROG_TYPE_TRACEPOINT
		t.Errorf("prog_type = %d, want 5 (tracepoint)", ev.ProgType)
	}
	if ev.SystemCall != "bpf" || ev.PID == 0 {
		t.Errorf("event = %+v", ev)
	}
}
