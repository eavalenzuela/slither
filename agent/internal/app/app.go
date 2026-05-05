// Package app wires the agent stages together and runs them under a single
// cancellation context. This is the top-level Phase 1 orchestrator.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/enricher"
	"github.com/t3rmit3/slither/agent/internal/extensions"
	"github.com/t3rmit3/slither/agent/internal/huntdispatch"
	"github.com/t3rmit3/slither/agent/internal/ioc"
	"github.com/t3rmit3/slither/agent/internal/output"
	"github.com/t3rmit3/slither/agent/internal/selfprotect"

	"github.com/t3rmit3/slither/agent/internal/backpressure"
	grpcsink "github.com/t3rmit3/slither/agent/internal/output/grpc"
	grpcbuffer "github.com/t3rmit3/slither/agent/internal/output/grpc/buffer"
	"github.com/t3rmit3/slither/agent/internal/respond"
	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	applog "github.com/t3rmit3/slither/pkg/log"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/version"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Run assembles every stage described in IMPLEMENTATION.md §3.1 and blocks
// until ctx is cancelled. Stages run as goroutines; the first error bubbles
// up and cancels siblings via the shared context.
//
// configPath is retained so SIGHUP can re-read the YAML for rules and file
// filters (§3.11 item 9). The hashing worker pool, collector layout, and
// device identity are fixed at startup — changing them requires restart.
func Run(ctx context.Context, cfg *config.Config, configPath string) error {
	if cfg == nil {
		return fmt.Errorf("app: nil config")
	}
	applog.Init(cfg.Agent.LogLevel)

	// Phase 5 #94 — self-protection bar. Order matters:
	//   1. CheckNotTraced first — if a tracer is already attached we
	//      want to fail loud before doing anything else (the agent's
	//      memory at this point still contains zero secrets, so an
	//      attached tracer is purely a "you're being monitored"
	//      signal, not an immediate exfil concern).
	//   2. SetDumpable next — closes the door on future PTRACE_ATTACH
	//      and on /proc/<pid> reads from non-owner UIDs.
	//   3. LockdownStateDirs — defense in depth atop systemd's
	//      StateDirectory= (irrelevant in containers).
	// Each call is best-effort + logs on failure rather than aborting
	// startup. CheckNotTraced is the one exception: tracer-attached
	// is a fatal startup condition.
	if err := selfprotect.CheckNotTraced(); err != nil {
		// Don't even continue to telemetry init — the audit row is
		// "agent refused to boot, tracer N had us pinned".
		return fmt.Errorf("app: %w", err)
	}
	if err := selfprotect.SetDumpable(); err != nil {
		slog.Warn("selfprotect: PR_SET_DUMPABLE failed; continuing without ptrace lockdown",
			"err", err)
	}
	if err := selfprotect.LockdownStateDirs("/var/lib/slither", "/etc/slither", "/var/log/slither"); err != nil {
		slog.Warn("selfprotect: state-dir lockdown failed; continuing",
			"err", err)
	}
	// Lowering CAP_BPF + CAP_PERFMON from ambient affects only what
	// forked subprocesses inherit on exec(2) — the agent itself keeps
	// permitted+effective caps for the lifetime of the process. We
	// can call this before BPF load because ambient isn't consulted
	// during bpf(2) calls; it's purely an exec-time inheritance knob.
	// Phase 5 #100's quarantine subprocess gets a strictly narrower
	// effective cap set than this lower-bound, so this is defense in
	// depth for that path (and any future fork+exec we add).
	if err := selfprotect.DropAmbientPostInit(); err != nil {
		slog.Warn("selfprotect: ambient cap drop failed; continuing",
			"err", err)
	}

	telem := telemetry.NewCounters()

	cg := collector.NewGroup(cfg.Collectors, telem)

	enr := enricher.New(cg, telem, enricher.Options{
		ParentChainDepth:    8,
		HashWorkers:         4,
		HashInlineTimeoutMs: 100,
		Device:              deviceIdentity(cfg),
		FileFilter:          cfg.Collectors.File,
	})

	iocStore := ioc.New()

	// Phase 5 #97 — backpressure cache. Exposed to the sink (so
	// server-pushed signals land here) and to the self-watch goroutine
	// (so DropsOutput-derived self-pressure also lands here). The
	// collector layer queries Cache.ShouldSample on the hot path.
	bpCache := backpressure.New()

	rules, err := loadRules(cfg, telem)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	eng := ruleengine.New(rules, telem)

	// Phase 5 #95 — open the tamper-evident audit chain. Best-effort:
	// a chain that won't open (e.g. /var/lib/slither not writable in
	// some constrained container shape) logs a warning and the agent
	// continues without local-side tamper evidence. The server-side
	// audit_log + CH detection-finding store remain authoritative.
	chain, chainErr := selfprotect.OpenChain("/var/lib/slither/log.chain")
	if chainErr != nil {
		slog.Warn("selfprotect: audit chain unavailable; continuing without local tamper-evidence",
			"err", chainErr)
		chain = nil
	} else {
		defer chain.Close()
	}
	eng.SetAuditChain(chain)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go watchReload(ctx, configPath, enr, eng, telem)

	// Phase 5 #97 — agent self-pressure watcher. Polls telem on a
	// fixed cadence (10 s default), computes the running drop_rate,
	// and updates bpCache's self channel. Server-pushed signals land
	// in the same cache via the sink's OnBackpressure callback; the
	// cache merges max(server, self).
	go backpressure.RunSelfWatch(ctx, bpCache, telem, backpressure.SelfWatchOptions{})

	// Phase 6 #107 — extensions supervisor. NewManager validates each
	// extension's verifier wiring; on error we surface it as a config
	// problem and refuse to boot rather than silently dropping
	// extensions (operator misspelled signature_verification etc.).
	extMgr, err := extensions.NewManager(cfg.Extensions, extensions.DefaultVerifierFor, deviceIdentity(cfg), telem, 1024)
	if err != nil {
		return fmt.Errorf("app: extensions: %w", err)
	}

	// Fan-in: extension OCSF events flow into the same channel the
	// engine reads. Native enricher events take priority via a
	// preferential select; under contention extension events queue on
	// the manager's own buffered channel rather than the merged feed.
	engineIn := mergeEvents(ctx, enr.Events(), extMgr.Events())

	// Sink construction is deferred until after extMgr exists so the
	// hunt dispatcher (Phase 6 #110) can wire OnHuntQuery → extMgr.
	sink, err := newSink(ctx, cfg, telem, eng, iocStore, chain, bpCache, extMgr)
	if err != nil {
		return fmt.Errorf("app: output sink: %w", err)
	}

	// Phase 6 #112 — chain-summary ticker. Every 5 minutes the agent
	// snapshots its tamper-evident chain (last_seq, last_hash,
	// windowed count) and pushes a ChainSummary onto the gRPC sink so
	// the server can cross-check against equivalent pg/CH rows.
	// Skipped when the chain is disabled (locked-down container, etc.)
	// or when the sink doesn't expose a summaries channel (stdout
	// sink in dev/scenario tests).
	if chain != nil {
		if csSink, ok := sink.(interface {
			ChainSummaries() chan<- *pb.ChainSummary
		}); ok {
			go runChainSummaryTicker(ctx, chain, csSink.ChainSummaries(), 5*time.Minute)
		}
	}

	errs := make(chan error, 5)
	go func() { errs <- cg.Run(ctx) }()
	go func() { errs <- enr.Run(ctx) }()
	go func() { errs <- extMgr.Run(ctx) }()
	go func() { errs <- eng.Run(ctx, engineIn) }()
	go func() { errs <- sink.Run(ctx, eng.Output()) }()

	// Return on first non-cancellation error; otherwise wait for ctx.
	var runErr error
	for i := 0; i < 5; i++ {
		select {
		case err := <-errs:
			if err != nil && !isCancelled(err, ctx) {
				cancel()
				runErr = err
				goto report
			}
		case <-ctx.Done():
			runErr = ctx.Err()
			goto report
		}
	}
report:
	// Phase 1 DiagReport: dump the final counter snapshot to stderr on
	// exit (exit-criterion #3 in §3.5). Load tests parse this to compute
	// drop-rate baselines; operators use it for quick health checks.
	//
	// Operational contract: scripts/load-test.sh greps `^telemetry:` from
	// agent stderr — keep this as a raw fmt.Fprintf rather than slog so
	// the line shape stays stable across log_level changes.
	snap := telem.Snapshot()
	fmt.Fprintf(os.Stderr,
		"telemetry: events=%d dropped=%d (collector=%d dispatch=%d enricher=%d engine=%d output=%d) detections=%d ringbuf_overflows=%d output_reconnects=%d heartbeats_sent=%d ext_spawned=%d ext_restarts=%d ext_signature_failures=%d ext_capability_violations=%d ext_events_emitted=%d ext_snapshots_requested=%d ext_snapshots_completed=%d ext_snapshots_failed=%d\n",
		snap.EventsProduced, snap.EventsDropped,
		snap.DropsCollector, snap.DropsDispatch, snap.DropsEnricher, snap.DropsEngine, snap.DropsOutput,
		snap.DetectionsFired, snap.RingbufOverflows,
		snap.OutputReconnects, snap.HeartbeatsSent,
		snap.ExtSpawned, snap.ExtRestarts, snap.ExtSignatureFailures, snap.ExtCapabilityViolations, snap.ExtEventsEmitted,
		snap.ExtSnapshotsRequested, snap.ExtSnapshotsCompleted, snap.ExtSnapshotsFailed)
	return runErr
}

// watchReload listens for SIGHUP and applies the reloadable subset of the
// YAML config — rule paths and file-collector globs — to the running
// enricher and rule engine. Errors are logged to stderr and the current
// runtime config is kept: a bad edit shouldn't silently wipe rules.
func watchReload(ctx context.Context, configPath string, enr enricher.Enricher, eng ruleengine.Engine, telem *telemetry.Counters) {
	if configPath == "" {
		return
	}
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			applyReload(configPath, enr, eng, telem)
		}
	}
}

func applyReload(configPath string, enr enricher.Enricher, eng ruleengine.Engine, telem *telemetry.Counters) {
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("reload: read config", "err", err)
		return
	}
	rules, err := loadRules(cfg, telem)
	if err != nil {
		slog.Error("reload: compile rules", "err", err)
		return
	}
	eng.ReplaceRules(rules)
	enr.ReloadFileFilter(cfg.Collectors.File)
	slog.Info("reload: applied rules", "rule_count", len(rules), "source", "sighup")
}

func isCancelled(err error, ctx context.Context) bool {
	return ctx.Err() != nil && (err == ctx.Err() || err == context.Canceled || err == context.DeadlineExceeded)
}

// newSink selects the output sink by config. "stdout" stays the default
// for dev + scenario tests; "grpc" opens a long-lived Session to the
// server. The grpc sink needs host_id on disk (written by the Enroll
// flow in #36) — a missing or empty file is a startup error, not a
// silent degradation. eng is wired in so the sink's ServerMessage
// receiver can apply server-pushed RuleSets via Engine.ReplaceRules.
func newSink(ctx context.Context, cfg *config.Config, telem *telemetry.Counters, eng ruleengine.Engine, iocStore *ioc.Store, chain *selfprotect.ChainWriter, bpCache *backpressure.Cache, extMgr *extensions.Manager) (output.Sink, error) {
	switch cfg.Output.Kind {
	case "stdout", "":
		return output.NewStdoutJSONL(os.Stdout), nil
	case "grpc":
		g := cfg.Output.GRPC
		var (
			emit           func([]string)
			submitResponse func(*pb.ResponseRequest)
			submitHunt     func(*pb.HuntQuery)
		)
		// Phase 4 #84: agent-side policy cache. Receives the latest
		// pb.HostPolicy from the server's session push and exposes a
		// Provider() the AutoResponder consults from the engine's hot
		// path. Empty cache = nil pointer = detect-only baseline.
		policyCache := respond.NewPolicyCache()

		// Phase 5 #96: optional offline disk buffer. Empty Dir disables
		// it (legacy memory-only drop-oldest behaviour). When configured,
		// in-flight envelopes spool to disk on overflow + replay on
		// every reconnect. Nil-safe: a buffer that fails to open warns
		// and continues without disk durability.
		var diskBuf *grpcbuffer.Buffer
		if g.Buffer.Dir != "" {
			b, bufErr := grpcbuffer.Open(grpcbuffer.Options{
				Dir:          g.Buffer.Dir,
				MaxBytes:     g.Buffer.DiskMaxBytes,
				MaxAge:       g.Buffer.MaxAge,
				SegmentBytes: g.Buffer.SegmentBytes,
			})
			if bufErr != nil {
				slog.Warn("grpc sink: disk buffer unavailable; continuing without offline durability",
					"err", bufErr, "dir", g.Buffer.Dir)
			} else {
				diskBuf = b
			}
		}

		sink, err := grpcsink.New(grpcsink.Options{
			ServerAddr:        g.ServerAddr,
			CAPath:            g.CAPath,
			CertPath:          g.CertPath,
			KeyPath:           g.KeyPath,
			HostIDPath:        g.HostIDPath,
			HeartbeatInterval: g.HeartbeatInterval,
			BufferSize:        g.BufferSize,
			AgentVersion:      version.Version,
			KeystoreDir:       g.KeystoreDir,
			KeystoreTPM:       cfg.Agent.Keystore.TPM,
			Buffer:            diskBuf,
			// emit is filled in below — applyRuleSetTo holds the
			// indirection so the callback closes over the variable
			// rather than the (still-nil) value at this point.
			OnRuleSet: applyRuleSetTo(eng, telem, iocStore, func(ws []string) {
				if emit != nil {
					emit(ws)
				}
			}),
			// Phase 4 #77: server-pushed ResponseRequests fan into
			// the executor via the same closure-indirection trick.
			OnResponseRequest: func(req *pb.ResponseRequest) {
				if submitResponse != nil {
					submitResponse(req)
				}
			},
			// Phase 4 #84: server-pushed HostPolicy snapshots land in
			// the cache the AutoResponder reads from.
			OnHostPolicy: func(p *pb.HostPolicy) {
				policyCache.Set(p)
			},
			// Phase 5 #97: server-pushed BackpressureSignal lands in
			// the agent's backpressure cache. Collectors consult
			// bpCache.ShouldSample on the hot path; the cache merges
			// this signal with the self-watcher's drop_rate-derived
			// self signal via max().
			OnBackpressure: func(sig *pb.BackpressureSignal) {
				if sig == nil {
					return
				}
				since := sig.GetSince().AsTime()
				bpCache.SetServer(sig.GetLevel(), sig.GetObservedDropRate(), since)
			},
			Backpressure: bpCache,
			// Phase 6 #110: server-pushed HuntQuery fans into the hunt
			// dispatcher; submitHunt is filled in below once the sink
			// + extension manager are both available.
			OnHuntQuery: func(q *pb.HuntQuery) {
				if submitHunt != nil {
					submitHunt(q)
				}
			},
		}, telem)
		if err != nil {
			return nil, err
		}
		emit = sink.EmitDiag
		// Build the executor against the sink's results channel +
		// a recorded telem source. Default-stub handlers return
		// FAILED + "not implemented"; #78-#81 SetHandler real ones.
		executor := respond.New(respond.Options{
			Results:    sink.Results(),
			Telem:      telem,
			AuditChain: chain, // Phase 5 #95 — nil-safe.
		})
		// Phase 4 #78: wire the real kill_process / kill_tree
		// handlers. Linux-only via build tag in respond/kill.go;
		// non-Linux builds (none today, but Phase 7 macOS / Windows
		// will need their own handlers) skip this call.
		respond.WireKillHandlers(executor)
		// Phase 4 #79: quarantine_file. Same Linux-build-tag pattern
		// — non-Linux falls back to the not-implemented default.
		respond.WireQuarantineHandlers(executor)
		// Phase 4 #80: isolate_host / unisolate_host. iptables-driven
		// slither-isolation chain; mgmt subnet from req.Target or
		// autoderived from /proc/net/route.
		respond.WireIsolationHandlers(executor)
		// Phase 4 #81: collect_artifacts. /proc snapshot + process
		// tree + recent journal as a tar.gz blob on ResponseResult.
		respond.WireCollectHandlers(executor)
		// Phase 4 #83: edge auto-respond bridge. Engine calls into
		// the AutoResponder when a rule with a `slither.response`
		// intent fires; the responder consults the cached HostPolicy
		// (Phase 4 #84) and either submits to the executor or stamps
		// the finding's would_have_executed marker.
		// Phase 6 #111: snapshot fanout. The AutoResponder also routes
		// `slither.snapshot: true` rules to extensions declaring
		// CAPABILITY_SNAPSHOT_PROVIDE. extMgrSnapshotAdapter shims the
		// extensions.Manager into respond.SnapshotDispatcher so the
		// respond package stays free of an extensions dependency.
		ar := respond.NewAutoResponder(executor, policyCache.Provider())
		ar.SetSnapshotDispatcher(extMgrSnapshotAdapter{m: extMgr}, telem)
		eng.SetAutoRespondHook(ar)
		submitResponse = func(req *pb.ResponseRequest) {
			// Submit is non-blocking; recv goroutine never stalls.
			// Handlers inherit the agent-process context so a Run
			// cancellation propagates into in-flight actions.
			_ = executor.Submit(ctx, req)
		}
		// Phase 6 #110: hunt dispatcher routes HuntQuery →
		// LiveQueryRequest on the LIVE_QUERY_RESPOND-capable extension
		// → HuntResult chunks on sink.HuntResults().
		hunts := huntdispatch.New(extMgr, sink.HuntResults())
		submitHunt = func(q *pb.HuntQuery) {
			hunts.Submit(ctx, q)
		}
		return sink, nil
	}
	return nil, fmt.Errorf("unknown output.kind %q", cfg.Output.Kind)
}

// applyRuleSetTo returns a callback that compiles a server-pushed
// RuleSet and swaps it into the running engine. Compile errors and
// ADR-0018 cap refusals on individual rules are skipped so one bad
// rule can't take the whole pack offline; refusals are emitted to
// the server via DiagReport (#57) so operators see what was rejected
// and why without scraping agent stderr.
//
// The rule-count transition is logged at info; steady-state pushes
// (debounced Refresh + 30s fallback poll) log at debug so operators
// running --log-level=info see only changes. The transition log is
// enough to diagnose the empty-RuleSet failure mode (e.g. server-side
// compile rejected every row) caught during #46 validation.
//
// emitDiag may be nil — in that case refusals still log locally but
// don't reach the server; production wires the gRPC sink's emitter.
func applyRuleSetTo(eng ruleengine.Engine, telem *telemetry.Counters, iocStore *ioc.Store, emitDiag func([]string)) func(*pb.RuleSet) {
	lastCount := -1
	return func(rs *pb.RuleSet) {
		compiled, warnings, err := compileRuleSet(rs, telem, iocStore)
		if err != nil {
			slog.Error("ruleset apply",
				"err", err,
				"ruleset_version", rs.GetVersion())
			return
		}
		fields := []any{
			"rule_count", len(compiled),
			"skipped_count", len(warnings),
			"ruleset_version", rs.GetVersion(),
			"source", "server-push",
		}
		if len(compiled) != lastCount {
			slog.Info("ruleset apply: rule count changed",
				append(fields, "previous_count", lastCount)...)
			lastCount = len(compiled)
		} else {
			slog.Debug("ruleset apply: steady state", fields...)
		}
		for _, w := range warnings {
			slog.Warn("ruleset apply: rule refused", "warning", w,
				"ruleset_version", rs.GetVersion())
		}
		eng.ReplaceRules(compiled)
		if emitDiag != nil && len(warnings) > 0 {
			emitDiag(warnings)
		}
	}
}

// mergeEvents fans the native enricher and extension supervisor event
// streams into a single channel for the rule engine. Both inputs are
// drained in parallel; the merged channel closes when both inputs do.
// Buffered to absorb bursty extension event rates without back-
// pressuring the enricher.
func mergeEvents(ctx context.Context, a, b <-chan ocsf.Event) <-chan ocsf.Event {
	out := make(chan ocsf.Event, 1024)
	go func() {
		defer close(out)
		for a != nil || b != nil {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-a:
				if !ok {
					a = nil
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			case ev, ok := <-b:
				if !ok {
					b = nil
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// deviceIdentity builds the OCSF Device stamp used in every emitted event.
// Phase 1 seeds it from os.Hostname + runtime so events validate; richer
// fields (host_id file, os release parsing, BTF kernel release) land with
// later Phase 1 polish.
func deviceIdentity(_ *config.Config) ocsf.Device {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return ocsf.Device{
		HostID:   host,
		Hostname: host,
		OSName:   runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}

// extMgrSnapshotAdapter shims an *extensions.Manager into the
// respond.SnapshotDispatcher interface. The respond package stays free
// of an extensions dependency this way (avoids pulling cosign /
// sigverify into every test build that imports respond).
//
// Phase 6 #111. The adapter only translates types — error mapping
// + per-provider channel handoff happen on the manager side.
type extMgrSnapshotAdapter struct {
	m *extensions.Manager
}

func (a extMgrSnapshotAdapter) DispatchSnapshot(ctx context.Context, req *pb.SnapshotRequest) ([]respond.SnapshotProviderReplies, error) {
	if a.m == nil {
		return nil, respond.ErrNoSnapshotProvider
	}
	out, err := a.m.DispatchSnapshot(ctx, req)
	if err != nil {
		if err == extensions.ErrNoSnapshotProvider {
			return nil, respond.ErrNoSnapshotProvider
		}
		return nil, err
	}
	mapped := make([]respond.SnapshotProviderReplies, 0, len(out))
	for _, d := range out {
		mapped = append(mapped, respond.SnapshotProviderReplies{
			ExtensionName: d.ExtensionName,
			Replies:       d.Replies,
		})
	}
	return mapped, nil
}

// runChainSummaryTicker fires a Phase 6 #112 ChainSummary onto the
// sink's chain-summary channel every interval. Drops on a wedged sink
// (capacity 4) rather than blocking — losing one summary is preferable
// to stalling the agent.
//
// On ctx cancellation the ticker exits without emitting a final
// summary; the server's verifier handles a missing summary as the
// "agent disconnected mid-window" case (no audit fired).
func runChainSummaryTicker(ctx context.Context, chain *selfprotect.ChainWriter, out chan<- *pb.ChainSummary, interval time.Duration) {
	if chain == nil || out == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			snap := chain.SnapshotAndReset()
			msg := &pb.ChainSummary{
				LastSeq:    snap.LastSeq,
				LastHash:   snap.LastHash,
				Count:      snap.Count,
				Since:      timestamppb.New(snap.Since),
				ObservedAt: timestamppb.New(snap.ObservedAt),
			}
			select {
			case out <- msg:
			default:
				slog.Warn("selfprotect: chain summary dropped (sink full)",
					"last_seq", snap.LastSeq, "count", snap.Count)
			}
		}
	}
}
