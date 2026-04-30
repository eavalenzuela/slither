package control

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// PolicyWatcher subscribes to LISTEN/NOTIFY signals from the
// host_response_policies table. *pg.Store satisfies it via
// WatchHostPolicies — but that signature returns a channel rather
// than taking a callback, so we wrap it in a small adapter.
type PolicyWatcher interface {
	WatchHostPolicies(ctx context.Context) (<-chan struct{}, error)
}

// RunPolicyHub drives a PolicyHub: initial Refresh, then a Refresh on
// every debounced NOTIFY plus the fallback ticker. Mirrors control.Run
// for the rule hub.
func RunPolicyHub(ctx context.Context, hub *PolicyHub, watcher PolicyWatcher, opts RunnerOptions) error {
	if hub == nil {
		return fmt.Errorf("control.RunPolicyHub: nil hub")
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 200 * time.Millisecond
	}
	if opts.FallbackPoll <= 0 {
		opts.FallbackPoll = 30 * time.Second
	}

	if err := hub.Refresh(ctx); err != nil {
		return fmt.Errorf("control.RunPolicyHub: initial refresh: %w", err)
	}

	notify := make(chan struct{}, 1)
	if watcher != nil {
		signals, err := watcher.WatchHostPolicies(ctx)
		if err != nil {
			slog.Warn("policy hub: watcher unavailable, falling back to poll only", "err", err)
		} else {
			go func() {
				for range signals {
					select {
					case notify <- struct{}{}:
					default:
					}
				}
			}()
		}
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
			if err := hub.Refresh(ctx); err != nil {
				slog.Warn("policy hub: debounced refresh failed", "err", err)
			}
		case <-tick.C:
			if err := hub.Refresh(ctx); err != nil {
				slog.Warn("policy hub: poll refresh failed", "err", err)
			}
		}
	}
}
