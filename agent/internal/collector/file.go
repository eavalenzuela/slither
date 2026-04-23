//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// fileCollector loads file.bpf.c, attaches its five syscall tracepoints, and
// drains the shared ringbuffer into RawFileEvent records.
//
// The in-kernel LPM_TRIE path prefilter sketched in IMPLEMENTATION.md §3.2 is
// deferred — events are emitted unfiltered from the kernel, and the enricher
// applies include/exclude globs from cfg userspace-side. cfg is retained on
// the struct so the trie wiring can be added without touching the collector
// API when it lands.
type fileCollector struct {
	out   chan<- pipeline.RawFileEvent
	cfg   config.FileCollector
	telem *telemetry.Counters
}

func newFileCollector(out chan<- pipeline.RawFileEvent, cfg config.FileCollector, telem *telemetry.Counters) Collector {
	return &fileCollector{out: out, cfg: cfg, telem: telem}
}

func (f *fileCollector) Name() string { return "file" }

func (f *fileCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("file: rlimit: %w", err)
	}

	var objs bpfpkg.FileObjects
	if err := bpfpkg.LoadFileObjects(&objs, nil); err != nil {
		return fmt.Errorf("file: load bpf objects: %w", err)
	}
	defer objs.Close()

	// Single attach to the generic raw_syscalls:sys_enter tracepoint. The
	// in-kernel switch in file.bpf.c dispatches to the openat/unlinkat/
	// renameat2/fchmodat/fchownat paths by syscall nr. Attaching here to the
	// per-syscall tracepoints (syscalls/sys_enter_openat etc.) hit -EACCES
	// on RHEL 9 / kernel 5.14 because the per-syscall trace event context
	// struct is nb_args-sized and our program's max_ctx_offset (derived from
	// the generic trace_event_raw_sys_enter with args[6] in vmlinux.h)
	// exceeded it. The raw_syscalls tracepoint uses the generic struct
	// natively, so the verifier's max_ctx_offset check always passes.
	l, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		return fmt.Errorf("file: attach raw_syscalls/sys_enter: %w", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("file: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return f.drain(ctx, rd)
}

func (f *fileCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("file: ringbuf read: %w", err)
		}

		var raw bpfpkg.FileFileEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			f.telem.IncDrops()
			continue
		}
		f.telem.IncEvents()

		select {
		case f.out <- decodeFileEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			f.telem.IncDropCollector()
		}
	}
}

// decodeFileEvent converts the packed BPF record into pipeline.RawFileEvent.
// Stamp Timestamp with wall-clock time at receive (kernel-monotonic rebasing
// is a Phase 5 concern; raw.TsNs is kept unused here, same as process).
func decodeFileEvent(r bpfpkg.FileFileEvent) pipeline.RawFileEvent {
	ev := pipeline.RawFileEvent{
		Kind:      decodeFileKind(r.Kind),
		PID:       r.Pid,
		UID:       r.Uid,
		Path:      cstr(r.Path[:]),
		NewPath:   cstr(r.Newpath[:]),
		Flags:     r.Flags,
		Mode:      r.Mode,
		Timestamp: time.Now(),
	}
	return ev
}

func decodeFileKind(k uint32) pipeline.RawFileKind {
	// Values mirror the SL_FILE_* enum in file.bpf.c.
	switch k {
	case 1:
		return pipeline.FileOpenCreate
	case 2:
		return pipeline.FileOpenWrite
	case 3:
		return pipeline.FileUnlink
	case 4:
		return pipeline.FileRename
	case 5:
		return pipeline.FileChmod
	case 6:
		return pipeline.FileChown
	default:
		return pipeline.FileUnknown
	}
}

