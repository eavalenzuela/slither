package collector

import (
	"context"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// netCollector will own net.bpf.c's ringbuffer reader.
type netCollector struct {
	out   chan<- pipeline.RawNetEvent
	telem *telemetry.Counters
}

func newNetCollector(out chan<- pipeline.RawNetEvent, telem *telemetry.Counters) Collector {
	return &netCollector{out: out, telem: telem}
}

func (n *netCollector) Name() string { return "net" }

// Run: Phase 1 task #22.
func (n *netCollector) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
