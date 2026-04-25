package control

import (
	"context"
	"fmt"
	"time"
)

// RuleWatcher subscribes to LISTEN/NOTIFY signals from the rules
// table. pg.Store.WatchRules satisfies it; tests can inject a stub
// without spinning up Postgres.
type RuleWatcher interface {
	WatchRules(ctx context.Context, onChange func()) error
}

// RunnerOptions tunes the Refresh cadence. Zero values fall back to
// documented defaults.
type RunnerOptions struct {
	// Debounce coalesces bursts of NOTIFY events. The default 200ms is
	// small enough to clear the §4.1 #39 sub-second convergence target
	// even on a multi-row UPDATE that fires the trigger N times.
	Debounce time.Duration

	// FallbackPoll triggers an unconditional Refresh every interval, in
	// case LISTEN/NOTIFY is missed (network blip, server restart on the
	// pg side). Defaults to 30s.
	FallbackPoll time.Duration
}

// Run drives the hub: an initial Refresh, then a Refresh on every
// debounced NOTIFY plus the fallback ticker. Blocks until ctx is
// cancelled.
func Run(ctx context.Context, hub *Hub, watcher RuleWatcher, opts RunnerOptions) error {
	if hub == nil {
		return fmt.Errorf("control.Run: nil hub")
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 200 * time.Millisecond
	}
	if opts.FallbackPoll <= 0 {
		opts.FallbackPoll = 30 * time.Second
	}

	// Initial load — failure is surfaced so the caller can decide whether
	// to keep starting (probably yes; an empty ruleset is still valid).
	if _, err := hub.Refresh(ctx); err != nil {
		return fmt.Errorf("control.Run: initial refresh: %w", err)
	}

	// notify is buffered 1 so the watcher goroutine never blocks on the
	// debouncer falling behind. Replacement-on-full keeps notifications
	// edge-triggered relative to the debounce window.
	notify := make(chan struct{}, 1)

	if watcher != nil {
		go func() {
			_ = watcher.WatchRules(ctx, func() {
				select {
				case notify <- struct{}{}:
				default:
				}
			})
		}()
	}

	tick := time.NewTicker(opts.FallbackPoll)
	defer tick.Stop()

	var debounceTimer *time.Timer
	startDebounce := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(opts.Debounce)
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(opts.Debounce)
	}
	debounceC := func() <-chan time.Time {
		if debounceTimer == nil {
			return nil
		}
		return debounceTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-notify:
			startDebounce()
		case <-debounceC():
			debounceTimer = nil
			if _, err := hub.Refresh(ctx); err != nil {
				// Refresh errors don't crash the runner — a future
				// NOTIFY or the fallback tick will retry. Log via the
				// hub's telemetry; the public error vocabulary is for
				// startup-time problems only.
				_ = err
			}
		case <-tick.C:
			if _, err := hub.Refresh(ctx); err != nil {
				_ = err
			}
		}
	}
}
