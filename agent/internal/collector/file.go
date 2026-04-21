package collector

import (
	"context"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// fileCollector will own file.bpf.c's ringbuffer reader and populate the
// in-kernel LPM path-prefix trie from config.
type fileCollector struct {
	out   chan<- pipeline.RawFileEvent
	cfg   config.FileCollector
	telem *telemetry.Counters
}

func newFileCollector(out chan<- pipeline.RawFileEvent, cfg config.FileCollector, telem *telemetry.Counters) Collector {
	return &fileCollector{out: out, cfg: cfg, telem: telem}
}

func (f *fileCollector) Name() string { return "file" }

// Run: Phase 1 task #21.
func (f *fileCollector) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
