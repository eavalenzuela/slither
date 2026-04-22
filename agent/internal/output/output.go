// Package output holds the event sinks. Phase 1 ships only the stdout
// JSON-lines sink; file-based output is a trivial Phase 1.x follow-up.
package output

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// Each event is marshalled with encoding/json and terminated with '\n'. The
// writer is wrapped in a bufio.Writer so syscalls amortise across events;
// every event is flushed immediately to keep live-tail consumers (systemd
// journal, scenario tests, operator `journalctl -f`) responsive.
func NewStdoutJSONL(w io.Writer) Sink {
	return &stdoutSink{w: w}
}

type stdoutSink struct {
	w io.Writer
}

func (s *stdoutSink) Run(ctx context.Context, in <-chan ocsf.Event) error {
	bw := bufio.NewWriter(s.w)
	enc := json.NewEncoder(bw)

	flush := func() {
		_ = bw.Flush()
	}
	defer flush()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if err := enc.Encode(ev); err != nil {
				return fmt.Errorf("output: encode %s: %w", ev.ClassID(), err)
			}
			// Flush per event: stdout is the only sink today, live-tail
			// semantics matter for ops, and throughput is well within what
			// an unbuffered Write-per-line can handle on the target fleet.
			if err := bw.Flush(); err != nil {
				return fmt.Errorf("output: flush: %w", err)
			}
		}
	}
}
