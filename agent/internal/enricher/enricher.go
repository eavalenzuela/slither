// Package enricher converts raw kernel events into OCSF events.
//
// Responsibilities (IMPLEMENTATION.md §3.4):
//   - Maintain a pid-keyed process cache populated on exec/fork, evicted on
//     exit (with a grace period for late-arriving events).
//   - Resolve ppid chains to depth 8 for process.parent_process in OCSF.
//   - Kick off async SHA-256 hashing on exec; attach inline if ready or emit
//     a followup event referencing event_id otherwise (Phase 1 task #23).
//   - Resolve uid → username via a /etc/passwd snapshot refreshed on SIGHUP.
package enricher

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ErrNotImplemented is returned by enrichment paths that have not been wired.
var ErrNotImplemented = errors.New("enricher: not yet implemented")

// Enricher is the interface exposed to the pipeline orchestrator.
type Enricher interface {
	// Run blocks until ctx is cancelled, draining raw events from the
	// collector group and emitting OCSF events on Events().
	Run(ctx context.Context) error
	// Events returns the channel of enriched OCSF events.
	Events() <-chan ocsf.Event
}

// Options parameterises the enricher's caches and workers.
type Options struct {
	// ParentChainDepth caps ppid-walk depth (default 8).
	ParentChainDepth int
	// HashWorkers bounds the async hashing pool (default 4).
	HashWorkers int
	// HashInlineTimeoutMs is the budget for inline hash attachment.
	HashInlineTimeoutMs int
	// CacheEvictionGrace is how long an exited pid sits in the cache so late
	// events can still resolve its identity (default 30s).
	CacheEvictionGrace time.Duration
	// PasswdPath overrides /etc/passwd (tests).
	PasswdPath string
	// ProcRoot overrides /proc (tests).
	ProcRoot string
	// Device is stamped into every emitted event's metadata.device.
	Device ocsf.Device
	// Now overrides time.Now (tests).
	Now func() time.Time
	// FileFilter supplies the include/exclude glob lists applied to file
	// events. Empty includes allow all; exclude always wins.
	FileFilter config.FileCollector
}

func (o *Options) applyDefaults() {
	if o.ParentChainDepth <= 0 {
		o.ParentChainDepth = 8
	}
	if o.HashWorkers <= 0 {
		o.HashWorkers = 4
	}
	if o.HashInlineTimeoutMs <= 0 {
		o.HashInlineTimeoutMs = 100
	}
	if o.CacheEvictionGrace <= 0 {
		o.CacheEvictionGrace = 30 * time.Second
	}
	if o.PasswdPath == "" {
		o.PasswdPath = "/etc/passwd"
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// New constructs an Enricher that reads from the given collector group.
func New(cg *collector.Group, telem *telemetry.Counters, opts Options) Enricher {
	opts.applyDefaults()
	return &enricher{
		cg:         cg,
		telem:      telem,
		opts:       opts,
		out:        make(chan ocsf.Event, 2048),
		cache:      newProcCache(),
		users:      newUserResolver(opts.PasswdPath),
		proc:       newProcReader(opts.ProcRoot),
		fileFilter: newPathGlob(opts.FileFilter.IncludePaths, opts.FileFilter.ExcludePaths),
	}
}

type enricher struct {
	cg         *collector.Group
	telem      *telemetry.Counters
	opts       Options
	out        chan ocsf.Event
	cache      *procCache
	users      *userResolver
	proc       *procReader
	fileFilter *pathGlob
}

func (e *enricher) Events() <-chan ocsf.Event { return e.out }

// Run pumps raw process events through the cache, converts them to OCSF, and
// emits on e.out. Returns when ctx is cancelled or the raw channel is closed.
func (e *enricher) Run(ctx context.Context) error {
	defer close(e.out)

	// Nothing to do if the collector group isn't wired. Keep the stage alive
	// until shutdown so the orchestrator's goroutine accounting stays simple.
	if e.cg == nil {
		<-ctx.Done()
		return ctx.Err()
	}

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	sweep := time.NewTicker(5 * time.Second)
	defer sweep.Stop()

	// A nil channel in a select case is permanently non-ready, so we can
	// always list both without branching on which collectors are enabled.
	var procIn <-chan pipeline.RawProcessEvent = e.cg.Process
	var fileIn <-chan pipeline.RawFileEvent = e.cg.File

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sighup:
			e.users.reload()
		case <-sweep.C:
			e.cache.evictExpired(e.opts.Now(), e.opts.CacheEvictionGrace)
		case raw, ok := <-procIn:
			if !ok {
				procIn = nil
				continue
			}
			e.handleProcess(ctx, raw)
		case raw, ok := <-fileIn:
			if !ok {
				fileIn = nil
				continue
			}
			e.handleFile(ctx, raw)
		}
	}
}

// handleProcess updates the cache and emits one OCSF ProcessActivity per
// raw event. Unknown kinds are dropped silently; the collector already logs
// its decode stats via telemetry.
func (e *enricher) handleProcess(ctx context.Context, raw pipeline.RawProcessEvent) {
	if raw.Kind == pipeline.ProcUnknown {
		e.telem.IncDrops()
		return
	}

	entry := procEntry{
		pid:       raw.PID,
		ppid:      raw.PPID,
		uid:       raw.UID,
		gid:       raw.GID,
		comm:      raw.Comm,
		createdAt: raw.Timestamp,
	}

	switch raw.Kind {
	case pipeline.ProcExec:
		// BPF doesn't carry ppid on exec; read once from /proc/<pid>/status.
		// Exe + cmdline follow the same pattern — BPF keeps the record small
		// and userspace resolves at event time.
		if entry.ppid == 0 {
			entry.ppid = e.proc.ppid(raw.PID)
		}
		entry.exe = e.proc.exe(raw.PID)
		entry.cmdline = e.proc.cmdline(raw.PID)
	case pipeline.ProcFork:
		// The BPF program captures the parent's comm at fork time. Try to
		// refresh from the child's /proc entry; on race (child not yet
		// scheduled) fall through with the parent's comm, which is still
		// useful for parent-chain correlation.
		if c := e.proc.comm(raw.PID); c != "" {
			entry.comm = c
		}
	}

	e.cache.upsert(entry)
	if raw.Kind == pipeline.ProcExit {
		e.cache.markExit(raw.PID, e.opts.Now())
	}

	// Rebuild from cache so we pick up any fields we already knew (e.g. exe
	// from a prior exec) when an exit event arrives bare.
	merged, ok := e.cache.get(raw.PID)
	if !ok {
		merged = entry
	}

	ev := e.buildOCSF(raw, merged)

	// Phase 1 queue policy (IMPLEMENTATION.md §3.5): Event priority. If the
	// rule-engine input is saturated we drop here and bump the drop counter.
	// Detection priority (higher) will get a non-dropping path in task #20.
	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDrops()
	}
}

func (e *enricher) buildOCSF(raw pipeline.RawProcessEvent, ent procEntry) *ocsf.ProcessActivity {
	username := e.users.Name(ent.uid)
	proc := processFromEntry(ent, username)

	if ent.ppid != 0 {
		proc.Parent = e.buildParentChain(ent.ppid, e.opts.ParentChainDepth)
	}

	actor := ocsf.Actor{
		User: ocsf.User{
			UID:  proc.UID,
			Name: username,
			Type: userType(ent.uid),
		},
	}
	if proc.Parent != nil {
		actor.Process = *proc.Parent
	} else {
		// No parent visible (pid 1 / early boot / cache miss before eviction
		// grace expires). Mirror the subject into the actor slot so the event
		// still validates and downstream rules have a non-zero pid to key on.
		actor.Process = *proc
	}

	activity := activityID(raw.Kind)
	ts := raw.Timestamp.UnixMilli()

	ev := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "process",
			EventCode: eventCode(raw.Kind),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassProcessActivity)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor:      actor,
		Process:    *proc,
	}
	if raw.Kind == pipeline.ProcExit {
		code := raw.ExitCode
		ev.ExitCode = &code
	}
	return ev
}

// buildParentChain walks ppid links up to remaining depth. Returns nil when
// pid is 0, depth is exhausted, or no cache entry exists and /proc lookups
// yield nothing usable.
func (e *enricher) buildParentChain(pid uint32, depth int) *ocsf.Process {
	if pid == 0 || depth <= 0 {
		return nil
	}
	if ent, ok := e.cache.get(pid); ok {
		p := processFromEntry(ent, e.users.Name(ent.uid))
		if ent.ppid != 0 && depth > 1 {
			p.Parent = e.buildParentChain(ent.ppid, depth-1)
		}
		return p
	}
	// Cache miss — best-effort resolve from /proc. Many ancestors (systemd,
	// the kernel's init idle task) sit stably under /proc and are cheap to
	// read once per chain walk.
	comm := e.proc.comm(pid)
	exe := e.proc.exe(pid)
	ppid := e.proc.ppid(pid)
	if comm == "" && exe == "" && ppid == 0 {
		return &ocsf.Process{PID: pid}
	}
	p := &ocsf.Process{PID: pid, Name: comm}
	if exe != "" {
		p.File = &ocsf.File{Path: exe, Name: filepath.Base(exe)}
	}
	if ppid != 0 && depth > 1 {
		p.Parent = e.buildParentChain(ppid, depth-1)
	}
	return p
}
