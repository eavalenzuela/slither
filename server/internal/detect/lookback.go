package detect

import (
	"context"
	"log/slog"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// EventReplayer is the dependency Phase 3 #59 cold-start uses to
// stream historical events back through a stateful plan's window at
// rule-load time. server/internal/store/ch.Store satisfies it via
// ReplayEnvelopes; tests can pass an in-memory stub without spinning
// up ClickHouse.
type EventReplayer interface {
	ReplayEnvelopes(
		ctx context.Context,
		classUID uint32,
		since, until time.Time,
		fn func(*pb.Envelope) error,
	) error
}

// runLookback replays the plan's timeframe window from the configured
// EventReplayer and walks each envelope through the plan exactly as a
// live event would, except the window's tick uses the envelope's own
// observed_at as the "now" — otherwise every replayed event would
// land in the same window slot and the count would race ahead of
// reality.
//
// Lookback is best-effort: a replay error degrades the plan to a
// cold start (plan still loads, just with no warm window) rather
// than blocking rule activation. Returns the number of events
// replayed plus a skipped flag (true when the timeframe exceeds
// MaxLookback or no replayer is configured).
func (e *Engine) runLookback(ctx context.Context, p *plan) (replayed int, skipped bool, err error) {
	if !p.lookback {
		return 0, true, nil
	}
	if e.replayer == nil {
		return 0, true, nil
	}
	if e.opts.MaxLookback > 0 && p.window.window > e.opts.MaxLookback {
		slog.Debug("detect: lookback skipped (timeframe exceeds MaxLookback)",
			"rule_uid", p.rule.ID,
			"timeframe", p.window.window,
			"max_lookback", e.opts.MaxLookback)
		return 0, true, nil
	}
	now := e.now()
	since := now.Add(-p.window.window)
	classUID := uint32(p.class)
	err = e.replayer.ReplayEnvelopes(ctx, classUID, since, now, func(env *pb.Envelope) error {
		replayed++
		// Decode + dispatch through the plan with the envelope's
		// observed_at as the tick clock. We don't pump through
		// Engine.process because that walks every plan; lookback is
		// scoped to one rule.
		ev, decodeErr := decodeEnvelope(env, p.class)
		if decodeErr != nil || ev == nil {
			return nil //nolint:nilerr // decode failure on a backfill row is non-fatal
		}
		ts := envelopeTime(env, now)
		switch p.kind {
		case planAggregation:
			e.runAggregation(ts, p, ev, env)
		case planNear:
			e.runNear(ts, p, ev, env)
		}
		return nil
	})
	if err != nil {
		slog.Warn("detect: lookback failed",
			"rule_uid", p.rule.ID, "replayed", replayed, "err", err)
		return replayed, false, err
	}
	slog.Info("detect: lookback complete",
		"rule_uid", p.rule.ID, "replayed", replayed,
		"timeframe", p.window.window)
	return replayed, false, nil
}

// envelopeTime prefers the envelope's stamped observed_at when
// present so window math reflects event time rather than wall-clock.
// CH should always populate ObservedAt, but the fallback to fallback
// (the engine's "now") keeps a missing field from breaking lookback.
func envelopeTime(env *pb.Envelope, fallback time.Time) time.Time {
	if env == nil {
		return fallback
	}
	if t := env.GetObservedAt(); t != nil {
		return t.AsTime()
	}
	return fallback
}
