package detect

import (
	"context"
	"log/slog"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// AlertWriter is the dependency Phase 3 #60 sink uses to land
// findings in the alerts table. *pg.Store satisfies it; tests pass an
// in-memory stub.
type AlertWriter interface {
	InsertAlert(ctx context.Context, ins pg.AlertInsert) (pg.AlertInsertResult, error)
}

// SinkTelemetry captures the per-finding outcome counters the sink
// bumps. Implemented by the server telemetry.Counters; tests can pass
// nil to opt out.
type SinkTelemetry interface {
	IncAlertsInserted()
	IncAlertsDeduped()
	IncAlertsErrored()
}

// RunFindingsSink drains the engine's Findings channel and lands each
// into the alerts table via writer.InsertAlert. Per-rule dedupe is
// enforced inside InsertAlert; this sink only wires the routing.
//
// Errors on individual inserts are logged but don't tear down the
// sink — one bad host_id parse or transient pg outage shouldn't lose
// the rest of the findings stream. Returns when findings closes
// (engine exited) or ctx is cancelled.
func RunFindingsSink(ctx context.Context, findings <-chan Finding, writer AlertWriter, telem SinkTelemetry) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f, ok := <-findings:
			if !ok {
				return nil
			}
			handleFinding(ctx, f, writer, telem)
		}
	}
}

func handleFinding(ctx context.Context, f Finding, writer AlertWriter, telem SinkTelemetry) {
	hostID := f.HostID
	if hostID == "" {
		// Cross-host findings the engine couldn't pin to a single host
		// can't land in alerts (alerts.host_id is NOT NULL). Phase 4
		// may add a synthetic fleet host for these; for #60 we drop
		// with a warn so operators see them in the log.
		slog.Warn("detect sink: dropping cross-host finding (alerts.host_id is NOT NULL)",
			"rule_uid", f.RuleID, "reason", f.Reason)
		return
	}
	res, err := writer.InsertAlert(ctx, pg.AlertInsert{
		RuleUID:    f.RuleID,
		HostID:     hostID,
		EventIDs:   f.EventIDs,
		Severity:   uint8(severityClamp(f.Severity)),
		ReasonCode: f.Reason,
	})
	if err != nil {
		if telem != nil {
			telem.IncAlertsErrored()
		}
		slog.Error("detect sink: insert alert",
			"rule_uid", f.RuleID, "host_id", hostID, "err", err)
		return
	}
	if res.DedupeSuppressed {
		if telem != nil {
			telem.IncAlertsDeduped()
		}
		slog.Debug("detect sink: dedupe suppressed",
			"rule_uid", f.RuleID, "host_id", hostID,
			"window_secs", res.DedupeWindowSecs)
		return
	}
	if telem != nil {
		telem.IncAlertsInserted()
	}
	slog.Info("detect sink: alert inserted",
		"alert_id", res.AlertID,
		"rule_uid", f.RuleID,
		"host_id", hostID,
		"severity", f.Severity)
}

// severityClamp pulls a uint32 down into the 1..6 range the alerts
// CHECK constraint enforces. The OCSF Severity enum tops out at 6
// (Other) so anything above is a malformed input — we collapse to
// Informational rather than reject.
func severityClamp(v uint32) uint32 {
	if v < 1 {
		return 1
	}
	if v > 6 {
		return 1
	}
	return v
}
