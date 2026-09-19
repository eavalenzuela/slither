//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// kernelCollector loads kernel.bpf.c: module load / unload / rejected
// load, BPF program load, and kprobe / uprobe attach via perf_event_open.
// See the C source for what each hook does and does not see.
type kernelCollector struct {
	out   chan<- pipeline.RawKernelEvent
	telem *telemetry.Counters

	// kprobeType / uprobeType are the dynamic PMU ids from
	// /sys/bus/event_source/devices/{kprobe,uprobe}/type. The BPF
	// program emits every dynamic-PMU perf_event_open; these decide
	// which two are probes. Zero means the PMU is absent on this kernel
	// (CONFIG_KPROBE_EVENTS / CONFIG_UPROBE_EVENTS off) and nothing
	// classifies as that kind.
	kprobeType uint32
	uprobeType uint32
}

func newKernelCollector(out chan<- pipeline.RawKernelEvent, telem *telemetry.Counters) Collector {
	return &kernelCollector{
		out:        out,
		telem:      telem,
		kprobeType: readPMUType("/sys/bus/event_source/devices/kprobe/type"),
		uprobeType: readPMUType("/sys/bus/event_source/devices/uprobe/type"),
	}
}

func (k *kernelCollector) Name() string { return "kernel" }

// readPMUType parses one sysfs PMU type file; 0 when absent or malformed.
func readPMUType(path string) uint32 {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is one of two compile-time sysfs constants (kprobe/uprobe PMU type)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func (k *kernelCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("kernel: rlimit: %w", err)
	}

	var objs bpfpkg.KernelObjects
	if lerr := bpfpkg.LoadKernelObjects(&objs, nil); lerr != nil {
		return fmt.Errorf("kernel: load bpf objects: %w", lerr)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	hooks := []struct {
		group, name string
		prog        *ebpf.Program
		// optional hooks may be missing on a kernel built without
		// CONFIG_MODULES — then nothing can load a module either, so
		// the other hooks still carry their weight.
		optional bool
	}{
		{"module", "module_load", objs.HandleModuleLoad, true},
		{"module", "module_free", objs.HandleModuleFree, true},
		{"syscalls", "sys_exit_init_module", objs.HandleInitModuleExit, false},
		{"syscalls", "sys_exit_finit_module", objs.HandleFinitModuleExit, false},
		{"syscalls", "sys_enter_bpf", objs.HandleBpf, false},
		{"syscalls", "sys_enter_perf_event_open", objs.HandlePerfEventOpen, false},
	}
	for _, h := range hooks {
		l, err := link.Tracepoint(h.group, h.name, h.prog, nil)
		if err != nil {
			if h.optional && errors.Is(err, os.ErrNotExist) {
				slog.Warn("kernel: tracepoint absent; skipping", "tracepoint", h.group+"/"+h.name)
				continue
			}
			return fmt.Errorf("kernel: attach tracepoint/%s/%s: %w", h.group, h.name, err)
		}
		links = append(links, l)
	}
	slog.Info("kernel collector attached", "probes", len(links),
		"kprobe_pmu", k.kprobeType, "uprobe_pmu", k.uprobeType)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("kernel: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return k.drain(ctx, rd)
}

func (k *kernelCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("kernel: ringbuf read: %w", err)
		}

		if len(rec.RawSample) < int(unsafe.Sizeof(bpfpkg.KernelKernelEvent{})) {
			k.telem.IncDrops()
			continue
		}
		raw := *(*bpfpkg.KernelKernelEvent)(unsafe.Pointer(&rec.RawSample[0])) //nolint:gosec // G103: deliberate zero-copy decode of BPF-emitted fixed-layout record

		ev, ok := k.decode(raw)
		if !ok {
			// A dynamic-PMU perf_event_open that is not a probe
			// (cpu, uncore, intel_pt, ...). Not telemetry, not a drop.
			continue
		}
		k.telem.IncEvents()

		select {
		case k.out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		default:
			k.telem.IncDropCollector()
		}
	}
}

// decode projects the wire record. ok is false for the one record type
// the BPF side cannot classify itself: a perf_event_open on a dynamic
// PMU that is neither the kprobe nor the uprobe PMU.
func (k *kernelCollector) decode(r bpfpkg.KernelKernelEvent) (pipeline.RawKernelEvent, bool) {
	ev := pipeline.RawKernelEvent{
		Kind:      decodeKernelKind(r.Kind),
		PID:       r.Tgid,
		UID:       r.Uid,
		Taints:    r.Taints,
		Name:      cstr(r.Name[:]),
		Comm:      cstr(r.Comm[:]),
		Timestamp: time.Now(),
	}
	switch ev.Kind {
	case pipeline.KernelModuleLoad, pipeline.KernelModuleUnload:
		ev.SystemCall = "init_module"
		if ev.Kind == pipeline.KernelModuleUnload {
			ev.SystemCall = "delete_module"
		}
	case pipeline.KernelModuleLoadRejected:
		ev.SystemCall = "init_module"
		if r.Result < 0 {
			ev.Errno = -r.Result
		}
	case pipeline.KernelBPFProgLoad:
		ev.SystemCall = "bpf"
		ev.ProgType = r.AttrType
	case pipeline.KernelProbeAttach:
		ev.SystemCall = "perf_event_open"
		switch {
		case k.kprobeType != 0 && r.AttrType == k.kprobeType:
			ev.Probe = "kprobe"
		case k.uprobeType != 0 && r.AttrType == k.uprobeType:
			ev.Probe = "uprobe"
		default:
			return pipeline.RawKernelEvent{}, false
		}
		ev.Name = cstr(r.Target[:])
		ev.Retprobe = r.Config&1 == 1
		ev.Offset = r.Config2
	}
	return ev, true
}

func decodeKernelKind(k uint32) pipeline.RawKernelKind {
	// Values mirror SL_KERNEL_* in kernel.bpf.c.
	switch k {
	case 1:
		return pipeline.KernelModuleLoad
	case 2:
		return pipeline.KernelModuleUnload
	case 3:
		return pipeline.KernelModuleLoadRejected
	case 4:
		return pipeline.KernelBPFProgLoad
	case 5:
		return pipeline.KernelProbeAttach
	default:
		return pipeline.KernelUnknown
	}
}
