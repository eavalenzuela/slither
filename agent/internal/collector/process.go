package collector

import (
	"context"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// processCollector will own the exec/exit/fork ringbuffer reader.
type processCollector struct {
	out   chan<- pipeline.RawProcessEvent
	telem *telemetry.Counters
}

func newProcessCollector(out chan<- pipeline.RawProcessEvent, telem *telemetry.Counters) Collector {
	return &processCollector{out: out, telem: telem}
}

func (p *processCollector) Name() string { return "process" }

// Run will load process.bpf.c, open its ringbuffer, decode records, and emit
// RawProcessEvent. Phase 1 task #17 fills this in.
func (p *processCollector) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
