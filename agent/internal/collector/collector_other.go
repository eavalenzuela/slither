//go:build !linux

package collector

import (
	"context"
	"log/slog"
	"sync"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// Non-Linux stub constructors. The Group orchestrator and the Collector
// interface in collector.go are platform-neutral, but the real event
// sources are eBPF (Linux, ADR-0010) and — landing in Phase 7 — Endpoint
// Security (macOS, ADR-0041). Until the macOS collectors land (#M-B2 /
// #M-B3), an enabled collector on a non-Linux build is a no-op that warns
// once and then blocks until shutdown. That keeps a dev or M-A2 macOS
// build booting cleanly through the same pipeline wiring while making it
// loud that no telemetry is flowing — rather than silently emitting
// nothing.

func newProcessCollector(_ chan<- pipeline.RawProcessEvent, _ *telemetry.Counters) Collector {
	return &noopCollector{name: "process"}
}

func newFileCollector(_ chan<- pipeline.RawFileEvent, _ config.FileCollector, _ *telemetry.Counters) Collector {
	return &noopCollector{name: "file"}
}

func newNetCollector(_ chan<- pipeline.RawNetEvent, _ *telemetry.Counters) Collector {
	return &noopCollector{name: "net"}
}

// noopCollector satisfies Collector without producing events. It exists so
// the agent compiles and runs on non-Linux platforms before native
// telemetry is implemented.
type noopCollector struct {
	name string
	once sync.Once
}

func (c *noopCollector) Name() string { return c.name }

func (c *noopCollector) Run(ctx context.Context) error {
	c.once.Do(func() {
		slog.Warn("collector has no implementation on this platform; no telemetry will be produced",
			"collector", c.name, "platform", "non-linux")
	})
	<-ctx.Done()
	return ctx.Err()
}
