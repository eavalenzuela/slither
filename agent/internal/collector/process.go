//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
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

// processCollector loads process.bpf.c, attaches its three sched tracepoints,
// and drains the shared ringbuffer into RawProcessEvent records.
type processCollector struct {
	out   chan<- pipeline.RawProcessEvent
	telem *telemetry.Counters
}

func newProcessCollector(out chan<- pipeline.RawProcessEvent, telem *telemetry.Counters) Collector {
	return &processCollector{out: out, telem: telem}
}

func (p *processCollector) Name() string { return "process" }

// Run loads the eBPF objects, attaches tracepoints, opens the ringbuffer,
// and forwards decoded events on p.out until ctx is cancelled.
func (p *processCollector) Run(ctx context.Context) error {
	// Lift MEMLOCK so the verifier can allocate map memory on kernels still
	// using rlimit-based BPF accounting (<5.11). No-op on memcg-accounted
	// kernels but harmless.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("process: rlimit: %w", err)
	}

	var objs bpfpkg.ProcessObjects
	if err := bpfpkg.LoadProcessObjects(&objs, nil); err != nil {
		return fmt.Errorf("process: load bpf objects: %w", err)
	}
	defer objs.Close()

	hooks := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.HandleExec},
		{"sched", "sched_process_exit", objs.HandleExit},
		{"sched", "sched_process_fork", objs.HandleFork},
	}
	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, h := range hooks {
		l, err := link.Tracepoint(h.group, h.name, h.prog, nil)
		if err != nil {
			return fmt.Errorf("process: attach %s/%s: %w", h.group, h.name, err)
		}
		links = append(links, l)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("process: open ringbuf: %w", err)
	}
	defer rd.Close()

	// Unblock the reader when ctx is cancelled.
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return p.drain(ctx, rd)
}

func (p *processCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("process: ringbuf read: %w", err)
		}

		// Direct struct cast over reflection-based binary.Read — the BPF
		// ringbuf reserves exact-size records and bpf2go emits the Go
		// struct with HostLayout matching the C wire layout on little-
		// endian amd64/arm64 (our only targets). Profile-level cost of
		// binary.Read with reflection on a 440-byte struct dominated the
		// single drain goroutine on RHEL 10 at 8k+ events/s and showed up
		// as collector-stage drops (task #15 step 10).
		if len(rec.RawSample) < int(unsafe.Sizeof(bpfpkg.ProcessProcessEvent{})) {
			p.telem.IncDrops()
			continue
		}
		raw := *(*bpfpkg.ProcessProcessEvent)(unsafe.Pointer(&rec.RawSample[0])) //nolint:gosec // G103: deliberate zero-copy decode of BPF-emitted fixed-layout record
		p.telem.IncEvents()

		select {
		case p.out <- decodeProcessEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel full — drop here to avoid stalling the ringbuf drain.
			// Priority-class drop policy proper lives on the inter-stage
			// queue (pipeline.Priority).
			p.telem.IncDropCollector()
		}
	}
}

// decodeProcessEvent converts the packed BPF record into the agent-internal
// RawProcessEvent. TsNs is kernel-monotonic (ktime_get_ns); wall-clock rebasing
// is a Phase 5 skew-monitoring item, so Phase 1 stamps Timestamp with
// time.Now() at receive time — accurate enough for ordering and correlation
// in the stateless rule engine.
func decodeProcessEvent(r bpfpkg.ProcessProcessEvent) pipeline.RawProcessEvent {
	return pipeline.RawProcessEvent{
		Kind:      decodeKind(r.Kind),
		PID:       r.Pid,
		PPID:      r.Ppid,
		TGID:      r.Tgid,
		UID:       r.Uid,
		GID:       r.Gid,
		Comm:      cstr(r.Comm[:]),
		Exe:       cstr(r.Exe[:]),
		Cmdline:   decodeCmdline(r.Cmdline[:], r.CmdlineLen),
		Timestamp: time.Now(),
		ExitCode:  r.ExitCode,
	}
}

// decodeCmdline converts the BPF cmdline blob to a space-separated string.
// argv in task->mm->arg_{start,end} is stored as null-separated bytes; we
// replace internal nulls with spaces up to cmdline_len. Length==0 means BPF
// didn't populate it (exec came from a kernel thread, or mm/arg reads
// failed) — fall back to empty and let the enricher hit /proc.
func decodeCmdline(buf []int8, n uint32) string {
	if n == 0 || int(n) > len(buf) {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(buf[i])
	}
	// Trim the final null if present; replace interior nulls with spaces.
	if b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	for i := range b {
		if b[i] == 0 {
			b[i] = ' '
		}
	}
	return string(b)
}

func decodeKind(k uint32) pipeline.RawProcessKind {
	// Values match the SL_PROC_* enum in process.bpf.c.
	switch k {
	case 1:
		return pipeline.ProcExec
	case 2:
		return pipeline.ProcExit
	case 3:
		return pipeline.ProcFork
	default:
		return pipeline.ProcUnknown
	}
}

// cstr converts a fixed-length NUL-terminated int8 buffer (the shape bpf2go
// emits for `char name[N]`) into a Go string. Used for comm fields and paths.
func cstr(b []int8) string {
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	buf := make([]byte, end)
	for i := 0; i < end; i++ {
		buf[i] = byte(b[i])
	}
	return string(buf)
}
