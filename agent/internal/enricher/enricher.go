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
	"sync"
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
	// ReloadFileFilter atomically swaps the file-path include/exclude globs.
	ReloadFileFilter(fc config.FileCollector)
}

// Options parameterises the enricher's caches and workers.
type Options struct {
	// ParentChainDepth caps ppid-walk depth (default 8).
	ParentChainDepth int
	// ProcessWorkers is the size of the pid-sharded worker pool that drains
	// the process collector channel. Each worker owns one shard of pids
	// (hash(pid) % N), so per-pid event order is preserved; the pool
	// parallelises the enricher's synchronous /proc backfill, which is the
	// Phase 1 load-test bottleneck (§3.11 task #30). Default 4.
	ProcessWorkers int
	// ProcessInboxSize buffers each worker's inbox. Too small and bursts
	// trip the dispatch drop path; too large just defers backpressure.
	// Default 1024 (total capacity = ProcessWorkers * ProcessInboxSize).
	ProcessInboxSize int
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
	if o.ProcessWorkers <= 0 {
		o.ProcessWorkers = 32
	}
	if o.ProcessInboxSize <= 0 {
		o.ProcessInboxSize = 2048
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
	inboxes := make([]chan pipeline.RawProcessEvent, opts.ProcessWorkers)
	for i := range inboxes {
		inboxes[i] = make(chan pipeline.RawProcessEvent, opts.ProcessInboxSize)
	}
	return &enricher{
		cg:             cg,
		telem:          telem,
		opts:           opts,
		out:            make(chan ocsf.Event, 16384),
		cache:          newProcCache(),
		users:          newUserResolver(opts.PasswdPath),
		proc:           newProcReader(opts.ProcRoot),
		fileFilter:     newPathGlob(opts.FileFilter.IncludePaths, opts.FileFilter.ExcludePaths),
		hasher:         newHasher(opts.HashWorkers),
		reloadFilterCh: make(chan config.FileCollector, 1),
		procInboxes:    inboxes,
	}
}

// ReloadFileFilter swaps the file-path include/exclude globs used by the
// enricher. Applied on the Run loop so reads stay race-free; calls made
// before Run is up or while a prior reload is still pending are coalesced.
func (e *enricher) ReloadFileFilter(fc config.FileCollector) {
	select {
	case e.reloadFilterCh <- fc:
	default:
		// Drain and replace so only the latest config survives.
		select {
		case <-e.reloadFilterCh:
		default:
		}
		select {
		case e.reloadFilterCh <- fc:
		default:
		}
	}
}

type enricher struct {
	cg             *collector.Group
	telem          *telemetry.Counters
	opts           Options
	out            chan ocsf.Event
	cache          *procCache
	users          *userResolver
	proc           *procReader
	fileFilter     *pathGlob
	hasher         *hasher
	reloadFilterCh chan config.FileCollector
	// procInboxes is the pid-sharded worker pool. Dispatch lives in Run's
	// main select; each inbox is drained by one goroutine running
	// handleProcess. Sharding by pid preserves per-pid event order (exec
	// before exit) while parallelising /proc backfill across workers.
	procInboxes []chan pipeline.RawProcessEvent
}

func (e *enricher) Events() <-chan ocsf.Event { return e.out }

// Run pumps raw process events through the cache, converts them to OCSF, and
// emits on e.out. Returns when ctx is cancelled or the raw channel is closed.
//
// Process events are dispatched to a pid-sharded worker pool
// (see Options.ProcessWorkers) to parallelise the synchronous /proc backfill
// done in handleProcess for ProcExec. The dispatcher runs in its own
// goroutine rather than the main select — RHEL 10 / 6.12 validation
// (task #29, 2026-04-22) showed that when the main select also handles
// file/net events inline, their /proc-read latency blocks process dispatch
// and the collector→enricher channel fills, surfacing as collector-stage
// drops under stress-ng --exec 100. File and net events stay on the main
// goroutine — they have no /proc read fan-out today, so parallelising them
// would add lock contention without throughput gain.
func (e *enricher) Run(ctx context.Context) error {
	defer func() {
		if e.hasher != nil {
			e.hasher.Close()
		}
	}()

	// Nothing to do if the collector group isn't wired. Keep the stage alive
	// until shutdown so the orchestrator's goroutine accounting stays simple.
	if e.cg == nil {
		<-ctx.Done()
		close(e.out)
		return ctx.Err()
	}

	// Start workers. Each drains one sharded inbox. ctx or a closed inbox
	// stops the worker.
	var wg sync.WaitGroup
	for i := range e.procInboxes {
		wg.Add(1)
		inbox := e.procInboxes[i]
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case raw, ok := <-inbox:
					if !ok {
						return
					}
					e.handleProcess(ctx, raw)
				}
			}
		}()
	}

	// Close worker inboxes exactly once — either when the dispatcher sees
	// procIn close, or when Run itself returns. Workers must drain and exit
	// before we close e.out, so output consumers never see a send on a
	// closed channel.
	var closeOnce sync.Once
	closeInboxes := func() {
		closeOnce.Do(func() {
			for _, w := range e.procInboxes {
				close(w)
			}
		})
	}

	// Dedicated process-dispatch goroutine. Isolating this from the main
	// select is load-bearing: on busy hosts (RHEL 10, 6.12) file/net events
	// handled inline in the main loop can stall for the duration of their
	// /proc-backed enrichment, during which the collector→enricher channel
	// (cg.Process) fills and the collector starts dropping at the ringbuf
	// drain boundary.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeInboxes()
		procIn := e.cg.Process
		for {
			select {
			case <-ctx.Done():
				return
			case raw, ok := <-procIn:
				if !ok {
					return
				}
				e.dispatchProcess(ctx, raw)
			}
		}
	}()

	defer func() {
		closeInboxes()
		wg.Wait()
		close(e.out)
	}()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	sweep := time.NewTicker(5 * time.Second)
	defer sweep.Stop()

	// A nil channel in a select case is permanently non-ready, so we can
	// always list both without branching on which collectors are enabled.
	// procIn is handled by the dedicated goroutine above.
	var fileIn <-chan pipeline.RawFileEvent = e.cg.File
	var netIn <-chan pipeline.RawNetEvent = e.cg.Net

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sighup:
			e.users.reload()
		case fc := <-e.reloadFilterCh:
			e.fileFilter = newPathGlob(fc.IncludePaths, fc.ExcludePaths)
		case <-sweep.C:
			e.cache.evictExpired(e.opts.Now(), e.opts.CacheEvictionGrace)
		case raw, ok := <-fileIn:
			if !ok {
				fileIn = nil
				continue
			}
			e.handleFile(ctx, raw)
		case raw, ok := <-netIn:
			if !ok {
				netIn = nil
				continue
			}
			e.handleNet(ctx, raw)
		}
	}
}

// dispatchProcess routes a raw process event to the pid-sharded worker inbox.
// Non-blocking on the inbox with drop-on-full, so a wedged worker cannot
// stall the main select loop. A full inbox counts as an enricher-side drop.
func (e *enricher) dispatchProcess(ctx context.Context, raw pipeline.RawProcessEvent) {
	shard := int(raw.PID) % len(e.procInboxes)
	select {
	case e.procInboxes[shard] <- raw:
	case <-ctx.Done():
	default:
		e.telem.IncDropDispatch()
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
		// BPF doesn't carry ppid on exec, and exec replaces the image so
		// exe/cmdline must come from /proc. Before the worker pool these
		// three syscalls ran serially and dominated per-event latency —
		// observed as 100% dispatch-attributed drops on Debian 13 under
		// stress-ng --exec 100. Two mitigations, both safe:
		//
		//   (1) Skip /proc/status if the cache already learnt ppid from a
		//       prior fork event for this pid (the common case; stress-ng
		//       always forks before exec).
		//   (2) Run the remaining independent /proc reads concurrently
		//       with sync.WaitGroup so per-event latency collapses from
		//       sum(ppid, exe, cmdline) to max(them).
		if entry.ppid == 0 {
			if prior, ok := e.cache.get(raw.PID); ok && prior.ppid != 0 {
				entry.ppid = prior.ppid
			}
		}

		var rg sync.WaitGroup
		var ppid uint32
		var exe, cmdline string
		needPpid := entry.ppid == 0
		if needPpid {
			rg.Add(1)
			go func() { defer rg.Done(); ppid = e.proc.ppid(raw.PID) }()
		}
		rg.Add(2)
		go func() { defer rg.Done(); exe = e.proc.exe(raw.PID) }()
		go func() { defer rg.Done(); cmdline = e.proc.cmdline(raw.PID) }()
		rg.Wait()
		if needPpid {
			entry.ppid = ppid
		}
		entry.exe = exe
		entry.cmdline = cmdline
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

	// Hash attachment is only meaningful on exec — fork/exit don't change the
	// image, and the caller already has the hash cached from the parent's exec
	// if anyone has looked at it. On exec we try the cache inline; on miss we
	// kick off an async computation bounded by HashInlineTimeoutMs. If the
	// result arrives in time we mutate the in-flight event before emit; if not
	// we emit bare and follow up with a correlation-tagged event when the
	// hash lands.
	if raw.Kind == pipeline.ProcExec && ev.Process.File != nil && ev.Process.File.Path != "" && e.hasher != nil {
		ch, cached, hash := e.hasher.Submit(ev.Process.File.Path)
		if cached {
			ev.Process.File.HashesSHA256 = hash
			e.emit(ctx, ev)
			return
		}
		if ch != nil {
			go e.awaitHash(ctx, ev, ch)
			return
		}
	}

	e.emit(ctx, ev)
}

// emit sends ev on the output channel with the non-blocking Event-priority
// policy from IMPLEMENTATION.md §3.5. A saturated downstream drops the event
// and bumps telemetry.
func (e *enricher) emit(ctx context.Context, ev ocsf.Event) {
	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDropEnricher()
	}
}

// awaitHash waits up to HashInlineTimeoutMs for an async hash computation to
// finish. Inside the budget we mutate the original event's File.HashesSHA256
// and emit it. Past the budget we emit the original bare and later, when the
// hash lands, emit a followup event with Metadata.CorrelationUID set to the
// original's UID so downstream consumers can stitch the two together.
func (e *enricher) awaitHash(ctx context.Context, ev *ocsf.ProcessActivity, ch <-chan string) {
	budget := time.Duration(e.opts.HashInlineTimeoutMs) * time.Millisecond
	t := time.NewTimer(budget)
	defer t.Stop()

	select {
	case hash, ok := <-ch:
		if ok && hash != "" && ev.Process.File != nil {
			ev.Process.File.HashesSHA256 = hash
		}
		e.emit(ctx, ev)
	case <-t.C:
		e.emit(ctx, ev)
		go e.followupHash(ctx, ev, ch)
	case <-ctx.Done():
	}
}

// followupHash waits on the remaining hash computation and emits a followup
// event correlated to the original. A zero-length hash (read failed, pool
// closed) produces no followup — there's nothing new to report.
func (e *enricher) followupHash(ctx context.Context, orig *ocsf.ProcessActivity, ch <-chan string) {
	var hash string
	select {
	case h, ok := <-ch:
		if !ok {
			return
		}
		hash = h
	case <-ctx.Done():
		return
	}
	if hash == "" {
		return
	}
	fu := buildHashFollowup(orig, hash)
	e.emit(ctx, fu)
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
			UID:       ocsf.NewUID(),
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
