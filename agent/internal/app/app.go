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

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/enricher"
	"github.com/t3rmit3/slither/agent/internal/ioc"
	"github.com/t3rmit3/slither/agent/internal/output"

	grpcsink "github.com/t3rmit3/slither/agent/internal/output/grpc"
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

	rules, err := loadRules(cfg, telem)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	eng := ruleengine.New(rules, telem)

	sink, err := newSink(ctx, cfg, telem, eng, iocStore)
	if err != nil {
		return fmt.Errorf("app: output sink: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go watchReload(ctx, configPath, enr, eng, telem)

	errs := make(chan error, 4)
	go func() { errs <- cg.Run(ctx) }()
	go func() { errs <- enr.Run(ctx) }()
	go func() { errs <- eng.Run(ctx, enr.Events()) }()
	go func() { errs <- sink.Run(ctx, eng.Output()) }()

	// Return on first non-cancellation error; otherwise wait for ctx.
	var runErr error
	for i := 0; i < 4; i++ {
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
		"telemetry: events=%d dropped=%d (collector=%d dispatch=%d enricher=%d engine=%d output=%d) detections=%d ringbuf_overflows=%d output_reconnects=%d heartbeats_sent=%d\n",
		snap.EventsProduced, snap.EventsDropped,
		snap.DropsCollector, snap.DropsDispatch, snap.DropsEnricher, snap.DropsEngine, snap.DropsOutput,
		snap.DetectionsFired, snap.RingbufOverflows,
		snap.OutputReconnects, snap.HeartbeatsSent)
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
func newSink(ctx context.Context, cfg *config.Config, telem *telemetry.Counters, eng ruleengine.Engine, iocStore *ioc.Store) (output.Sink, error) {
	switch cfg.Output.Kind {
	case "stdout", "":
		return output.NewStdoutJSONL(os.Stdout), nil
	case "grpc":
		g := cfg.Output.GRPC
		var (
			emit           func([]string)
			submitResponse func(*pb.ResponseRequest)
		)
		sink, err := grpcsink.New(grpcsink.Options{
			ServerAddr:        g.ServerAddr,
			CAPath:            g.CAPath,
			CertPath:          g.CertPath,
			KeyPath:           g.KeyPath,
			HostIDPath:        g.HostIDPath,
			HeartbeatInterval: g.HeartbeatInterval,
			BufferSize:        g.BufferSize,
			AgentVersion:      version.Version,
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
		}, telem)
		if err != nil {
			return nil, err
		}
		emit = sink.EmitDiag
		// Build the executor against the sink's results channel +
		// a recorded telem source. Default-stub handlers return
		// FAILED + "not implemented"; #78-#81 SetHandler real ones.
		executor := respond.New(respond.Options{
			Results: sink.Results(),
			Telem:   telem,
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
		// and either submits to the executor or stamps the finding's
		// would_have_executed marker. PolicyProvider stays nil here
		// — #84 wires the real NOTIFY-driven cache. nil → detect-only
		// baseline, which is the safe default for the gap.
		eng.SetAutoRespondHook(respond.NewAutoResponder(executor, nil))
		submitResponse = func(req *pb.ResponseRequest) {
			// Submit is non-blocking; recv goroutine never stalls.
			// Handlers inherit the agent-process context so a Run
			// cancellation propagates into in-flight actions.
			_ = executor.Submit(ctx, req)
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
