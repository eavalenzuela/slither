package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// AlertWriter is the dependency Phase 3 #60 alert routing uses to
// land OCSF DetectionFinding envelopes in the alerts table. *pg.Store
// satisfies it; tests pass an in-memory stub. Defined locally to
// avoid an ingest→detect import cycle.
type AlertWriter interface {
	InsertAlert(ctx context.Context, ins pg.AlertInsert) (pg.AlertInsertResult, error)
}

// AlertRouterTelemetry is the small surface the router needs from the
// server's telemetry counters. Defined locally so ingest doesn't need
// a hard dependency on the server's telemetry struct.
type AlertRouterTelemetry interface {
	IncAlertsInserted()
	IncAlertsDeduped()
	IncAlertsErrored()
}

// RouteAlerts subscribes name to bus and lands every OCSF
// DetectionFinding envelope (class_uid 2004) into the alerts table
// via writer.InsertAlert. Per-rule dedupe (Phase 3 #60) is enforced
// inside InsertAlert.
//
// Edge agents emit DetectionFinding events through the same Session
// stream as their per-class telemetry events; this router picks them
// off the bus alongside the ClickHouse writer + live-tail SSE so
// alerts get the same backpressure-tolerant fan-out as everything
// else. A subscriber with a small buffer fits the alert-traffic
// shape — alerts arrive sporadically, not at event-stream rate.
//
// Returns when ctx is cancelled or the bus closes.
func RouteAlerts(ctx context.Context, bus *Bus, name string, writer AlertWriter, telem AlertRouterTelemetry) error {
	if bus == nil {
		return errors.New("ingest.RouteAlerts: nil bus")
	}
	if writer == nil {
		return errors.New("ingest.RouteAlerts: nil writer")
	}
	envs := bus.Subscribe(name, 256)
	defer bus.Unsubscribe(name)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env, ok := <-envs:
			if !ok {
				return nil
			}
			handleEnvelope(ctx, env, writer, telem)
		}
	}
}

func handleEnvelope(ctx context.Context, env *pb.Envelope, writer AlertWriter, telem AlertRouterTelemetry) {
	if env == nil {
		return
	}
	if env.GetClassId() != pb.OcsfClassId(ocsf.ClassDetectionFinding) {
		return
	}
	var f ocsf.DetectionFinding
	if err := json.Unmarshal(env.GetPayload(), &f); err != nil {
		slog.Warn("ingest router: decode detection_finding",
			"event_id", env.GetEventId(), "err", err)
		return
	}
	if f.RuleInfo.UID == "" {
		slog.Warn("ingest router: detection_finding missing rule.uid",
			"event_id", env.GetEventId())
		return
	}
	hostID := env.GetHostId()
	if hostID == "" {
		slog.Warn("ingest router: detection_finding missing host_id",
			"event_id", env.GetEventId(), "rule_uid", f.RuleInfo.UID)
		return
	}
	severity := uint8(f.Severity)
	if severity < 1 || severity > 6 {
		severity = 1
	}
	res, err := writer.InsertAlert(ctx, pg.AlertInsert{
		RuleUID:    f.RuleInfo.UID,
		HostID:     hostID,
		EventIDs:   f.TriggeringEventIDs,
		Severity:   severity,
		ReasonCode: f.Finding.Title,
	})
	if err != nil {
		if telem != nil {
			telem.IncAlertsErrored()
		}
		slog.Error("ingest router: insert alert",
			"rule_uid", f.RuleInfo.UID, "host_id", hostID, "err", err)
		return
	}
	if res.DedupeSuppressed {
		if telem != nil {
			telem.IncAlertsDeduped()
		}
		slog.Debug("ingest router: dedupe suppressed",
			"rule_uid", f.RuleInfo.UID, "host_id", hostID,
			"window_secs", res.DedupeWindowSecs)
		return
	}
	if telem != nil {
		telem.IncAlertsInserted()
	}
	slog.Info("ingest router: alert inserted",
		"alert_id", res.AlertID,
		"rule_uid", f.RuleInfo.UID,
		"host_id", hostID,
		"severity", severity)
}
