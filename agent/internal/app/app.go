// Package app wires the agent stages together and runs them under a single
// cancellation context. This is the top-level Phase 1 orchestrator.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/enricher"
	"github.com/t3rmit3/slither/agent/internal/output"

	grpcsink "github.com/t3rmit3/slither/agent/internal/output/grpc"
	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
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

	telem := telemetry.NewCounters()

	cg := collector.NewGroup(cfg.Collectors, telem)

	enr := enricher.New(cg, telem, enricher.Options{
		ParentChainDepth:    8,
		HashWorkers:         4,
		HashInlineTimeoutMs: 100,
		Device:              deviceIdentity(cfg),
		FileFilter:          cfg.Collectors.File,
	})

	rules, err := loadRules(cfg)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	eng := ruleengine.New(rules, telem)

	sink, err := newSink(cfg, telem, eng)
	if err != nil {
		return fmt.Errorf("app: output sink: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go watchReload(ctx, configPath, enr, eng)

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
func watchReload(ctx context.Context, configPath string, enr enricher.Enricher, eng ruleengine.Engine) {
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
			applyReload(configPath, enr, eng)
		}
	}
}

func applyReload(configPath string, enr enricher.Enricher, eng ruleengine.Engine) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reload: %v\n", err)
		return
	}
	rules, err := loadRules(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reload rules: %v\n", err)
		return
	}
	eng.ReplaceRules(rules)
	enr.ReloadFileFilter(cfg.Collectors.File)
	fmt.Fprintf(os.Stderr, "reload: applied %d rules\n", len(rules))
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
func newSink(cfg *config.Config, telem *telemetry.Counters, eng ruleengine.Engine) (output.Sink, error) {
	switch cfg.Output.Kind {
	case "stdout", "":
		return output.NewStdoutJSONL(os.Stdout), nil
	case "grpc":
		g := cfg.Output.GRPC
		return grpcsink.New(grpcsink.Options{
			ServerAddr:        g.ServerAddr,
			CAPath:            g.CAPath,
			CertPath:          g.CertPath,
			KeyPath:           g.KeyPath,
			HostIDPath:        g.HostIDPath,
			HeartbeatInterval: g.HeartbeatInterval,
			BufferSize:        g.BufferSize,
			AgentVersion:      version.Version,
			OnRuleSet:         applyRuleSetTo(eng),
		}, telem)
	}
	return nil, fmt.Errorf("unknown output.kind %q", cfg.Output.Kind)
}

// applyRuleSetTo returns a callback that compiles a server-pushed
// RuleSet and swaps it into the running engine. Compile errors on
// individual rules are silently skipped so a single bad rule from the
// server can't take all rules offline; the surviving rules ship.
//
// A single-line stderr summary fires only when the rule count changes
// between successive applies — the steady-state pushes (debounced
// Refresh + 30s fallback poll) would otherwise spam every cycle. The
// transition log is enough to diagnose the empty-RuleSet failure mode
// (e.g. server-side compile rejected every row) caught during #46
// validation.
func applyRuleSetTo(eng ruleengine.Engine) func(*pb.RuleSet) {
	lastCount := -1
	return func(rs *pb.RuleSet) {
		compiled, skipped, err := compileRuleSet(rs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: ruleset apply: %v\n", err)
			return
		}
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "agent: ruleset apply: %d rule(s) skipped (compile/version mismatch)\n", skipped)
		}
		if len(compiled) != lastCount {
			fmt.Fprintf(os.Stderr, "agent: ruleset apply: engine now running %d rule(s) (was %d)\n", len(compiled), lastCount)
			lastCount = len(compiled)
		}
		eng.ReplaceRules(compiled)
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
