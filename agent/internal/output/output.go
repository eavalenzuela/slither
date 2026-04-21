// Package output holds the event sinks. Phase 1 ships only the stdout
// JSON-lines sink; file-based output is a trivial Phase 1.x follow-up.
package output

import (
	"context"
	"errors"
	"io"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ErrNotImplemented is returned by sinks that have not been wired yet.
var ErrNotImplemented = errors.New("output: not yet implemented")

// Sink emits events to a destination. All methods must be safe for concurrent
// use; implementations typically serialise through an internal goroutine.
type Sink interface {
	// Run blocks, draining in until ctx is cancelled. On shutdown, any
	// buffered bytes must be flushed before returning.
	Run(ctx context.Context, in <-chan ocsf.Event) error
}

// NewStdoutJSONL returns a JSON-lines sink writing to w (typically os.Stdout).
func NewStdoutJSONL(w io.Writer) Sink {
	return &stdoutSink{w: w}
}

type stdoutSink struct {
	w io.Writer
}

// Run: Phase 1 task #17 drops in the real implementation once events are
// actually flowing end-to-end.
func (s *stdoutSink) Run(ctx context.Context, in <-chan ocsf.Event) error {
	<-ctx.Done()
	return ctx.Err()
}
