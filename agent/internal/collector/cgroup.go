//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// cgroupCollector loads cgroup.bpf.c: cgroup directory create / remove,
// which is the runtime-agnostic container create / stop signal. The
// enricher decides which cgroups are containers (see enricher/containers.go).
type cgroupCollector struct {
	out   chan<- pipeline.RawCgroupEvent
	telem *telemetry.Counters
}

func newCgroupCollector(out chan<- pipeline.RawCgroupEvent, telem *telemetry.Counters) Collector {
	return &cgroupCollector{out: out, telem: telem}
}

func (c *cgroupCollector) Name() string { return "container" }

func (c *cgroupCollector) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("container: rlimit: %w", err)
	}

	var objs bpfpkg.CgroupObjects
	if lerr := bpfpkg.LoadCgroupObjects(&objs, nil); lerr != nil {
		return fmt.Errorf("container: load bpf objects: %w", lerr)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	mk, err := link.Tracepoint("cgroup", "cgroup_mkdir", objs.HandleCgroupMkdir, nil)
	if err != nil {
		return fmt.Errorf("container: attach tracepoint/cgroup/cgroup_mkdir: %w", err)
	}
	links = append(links, mk)
	rm, err := link.Tracepoint("cgroup", "cgroup_rmdir", objs.HandleCgroupRmdir, nil)
	if err != nil {
		return fmt.Errorf("container: attach tracepoint/cgroup/cgroup_rmdir: %w", err)
	}
	links = append(links, rm)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("container: open ringbuf: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	return c.drain(ctx, rd)
}

func (c *cgroupCollector) drain(ctx context.Context, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("container: ringbuf read: %w", err)
		}

		if len(rec.RawSample) < int(unsafe.Sizeof(bpfpkg.CgroupCgroupEvent{})) {
			c.telem.IncDrops()
			continue
		}
		raw := *(*bpfpkg.CgroupCgroupEvent)(unsafe.Pointer(&rec.RawSample[0])) //nolint:gosec // G103: deliberate zero-copy decode of BPF-emitted fixed-layout record
		c.telem.IncEvents()

		select {
		case c.out <- decodeCgroupEvent(raw):
		case <-ctx.Done():
			return ctx.Err()
		default:
			c.telem.IncDropCollector()
		}
	}
}

func decodeCgroupEvent(r bpfpkg.CgroupCgroupEvent) pipeline.RawCgroupEvent {
	return pipeline.RawCgroupEvent{
		Kind:      decodeCgroupKind(r.Kind),
		PID:       r.Tgid,
		UID:       r.Uid,
		Root:      r.Root,
		ID:        r.Id,
		Path:      cstr(r.Path[:]),
		Comm:      cstr(r.Comm[:]),
		Timestamp: time.Now(),
	}
}

func decodeCgroupKind(k uint32) pipeline.RawCgroupKind {
	// Values mirror SL_CGROUP_* in cgroup.bpf.c.
	switch k {
	case 1:
		return pipeline.CgroupMkdir
	case 2:
		return pipeline.CgroupRmdir
	default:
		return pipeline.CgroupUnknown
	}
}
