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

	hooks := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_openat", objs.HandleOpenat},
		{"syscalls", "sys_enter_unlinkat", objs.HandleUnlinkat},
		{"syscalls", "sys_enter_renameat2", objs.HandleRenameat2},
		{"syscalls", "sys_enter_fchmodat", objs.HandleFchmodat},
		{"syscalls", "sys_enter_fchownat", objs.HandleFchownat},
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
			return fmt.Errorf("file: attach %s/%s: %w", h.group, h.name, err)
		}
		links = append(links, l)
	}

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
			f.telem.IncDrops()
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

