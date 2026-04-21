// Package app wires the agent stages together and runs them under a single
// cancellation context. This is the top-level Phase 1 orchestrator.
package app

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/enricher"
	"github.com/t3rmit3/slither/agent/internal/output"
	"github.com/t3rmit3/slither/agent/internal/ruleengine"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// Run assembles every stage described in IMPLEMENTATION.md §3.1 and blocks
// until ctx is cancelled. Stages run as goroutines; the first error bubbles
// up and cancels siblings via the shared context.
func Run(ctx context.Context, cfg *config.Config) error {
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
	})

	rules, err := loadRules(cfg)
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	eng := ruleengine.New(rules, telem)

	sink := output.NewStdoutJSONL(os.Stdout)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 4)
	go func() { errs <- cg.Run(ctx) }()
	go func() { errs <- enr.Run(ctx) }()
	go func() { errs <- eng.Run(ctx, enr.Events()) }()
	go func() { errs <- sink.Run(ctx, eng.Output()) }()

	// Return on first non-cancellation error; otherwise wait for ctx.
	for i := 0; i < 4; i++ {
		select {
		case err := <-errs:
			if err != nil && !isCancelled(err, ctx) {
				cancel()
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func isCancelled(err error, ctx context.Context) bool {
	return ctx.Err() != nil && (err == ctx.Err() || err == context.Canceled || err == context.DeadlineExceeded)
}

// deviceIdentity builds the OCSF Device stamp used in every emitted event.
// Phase 1 seeds it from os.Hostname + runtime so events validate; richer
// fields (host_id file, os release parsing, BTF kernel release) land with
// the full config loader in task #24.
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
