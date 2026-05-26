// Package collector turns a platform's kernel telemetry into typed
// raw-event channels consumed by the enricher.
//
// Each collector (process, file, net) owns its reader goroutine and its
// output channel. The aggregate is wired by Group. The Group orchestrator
// and the Collector interface are platform-neutral; the per-collector
// constructors are platform-specific — eBPF on Linux (ADR-0010), Endpoint
// Security on macOS (ADR-0041, Phase 7). Non-Linux builds compile against
// no-op constructors in collector_other.go until those land.
package collector

import (
	"context"
	"errors"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// ErrNotImplemented is returned by collectors that have not been wired yet.
var ErrNotImplemented = errors.New("collector: not yet implemented")

// Collector is a single kernel-telemetry event source.
type Collector interface {
	// Name identifies the collector in logs (e.g. "process", "file", "net").
	Name() string
	// Run blocks until ctx is cancelled or an unrecoverable error occurs.
	Run(ctx context.Context) error
}

// Group wires the three Phase 1 collectors and exposes one channel per raw
// event family. Construction does not touch the kernel; Run does.
type Group struct {
	Process chan pipeline.RawProcessEvent
	File    chan pipeline.RawFileEvent
	Net     chan pipeline.RawNetEvent

	cfg       config.Collectors
	telem     *telemetry.Counters
	processor Collector
	filer     Collector
	networker Collector
}

// NewGroup constructs collectors honouring the enable flags in cfg. The
// individual collectors are created as stubs until §3.2 programs land.
func NewGroup(cfg config.Collectors, telem *telemetry.Counters) *Group {
	g := &Group{
		Process: make(chan pipeline.RawProcessEvent, 65536),
		File:    make(chan pipeline.RawFileEvent, 16384),
		Net:     make(chan pipeline.RawNetEvent, 16384),
		cfg:     cfg,
		telem:   telem,
	}
	if cfg.Process.Enabled {
		g.processor = newProcessCollector(g.Process, telem)
	}
	if cfg.File.Enabled {
		g.filer = newFileCollector(g.File, cfg.File, telem)
	}
	if cfg.Net.Enabled {
		g.networker = newNetCollector(g.Net, telem)
	}
	return g
}

// Run starts every enabled collector and returns when ctx is cancelled or
// any collector returns an error.
func (g *Group) Run(ctx context.Context) error {
	errCh := make(chan error, 3)
	started := 0
	for _, c := range []Collector{g.processor, g.filer, g.networker} {
		if c == nil {
			continue
		}
		started++
		go func(c Collector) { errCh <- c.Run(ctx) }(c)
	}
	if started == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	// Return on first collector exit; caller cancels ctx to stop the rest.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
