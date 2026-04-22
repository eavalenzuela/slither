//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

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

		var raw bpfpkg.ProcessProcessEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			p.telem.IncDrops()
			continue
		}
		p.telem.IncEvents()

		select {
		case p.out <- decodeProcessEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel full — drop here to avoid stalling the ringbuf drain.
			// Priority-class drop policy proper lives on the inter-stage
			// queue (pipeline.Priority).
			p.telem.IncDrops()
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
		Timestamp: time.Now(),
		ExitCode:  r.ExitCode,
	}
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
