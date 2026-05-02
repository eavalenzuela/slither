package backpressure

import (
	"testing"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

func TestClassify_NoEventsIsNormal(t *testing.T) {
	t.Parallel()
	prev := telemetry.Snapshot{EventsProduced: 100, EventsDropped: 50}
	cur := telemetry.Snapshot{EventsProduced: 100, EventsDropped: 50}
	level, frac := classify(prev, cur, SelfWatchOptions{
		ElevatedThreshold: 0.05, CriticalThreshold: 0.2,
	})
	if level != LevelNormal {
		t.Errorf("idle window classified as %v, want NORMAL", level)
	}
	if frac != 0 {
		t.Errorf("frac = %v, want 0 (no events)", frac)
	}
}

func TestClassify_BelowThresholdIsNormal(t *testing.T) {
	t.Parallel()
	// 1000 events, 30 dropped → 3 % drop rate, below 5 % threshold.
	prev := telemetry.Snapshot{EventsProduced: 0, EventsDropped: 0}
	cur := telemetry.Snapshot{EventsProduced: 1000, EventsDropped: 30}
	level, _ := classify(prev, cur, SelfWatchOptions{
		ElevatedThreshold: 0.05, CriticalThreshold: 0.2,
	})
	if level != LevelNormal {
		t.Errorf("3 %% drop classified as %v, want NORMAL", level)
	}
}

func TestClassify_ElevatedRange(t *testing.T) {
	t.Parallel()
	// 1000 events, 80 dropped → 8 % drop rate.
	prev := telemetry.Snapshot{}
	cur := telemetry.Snapshot{EventsProduced: 1000, EventsDropped: 80}
	level, frac := classify(prev, cur, SelfWatchOptions{
		ElevatedThreshold: 0.05, CriticalThreshold: 0.2,
	})
	if level != LevelElevated {
		t.Errorf("8 %% drop classified as %v, want ELEVATED", level)
	}
	if frac < 0.07 || frac > 0.09 {
		t.Errorf("frac = %v, want ~0.08", frac)
	}
}

func TestClassify_CriticalAtThreshold(t *testing.T) {
	t.Parallel()
	// 1000 events, 200 dropped → exactly 20 % → CRITICAL (>= boundary).
	prev := telemetry.Snapshot{}
	cur := telemetry.Snapshot{EventsProduced: 1000, EventsDropped: 200}
	level, _ := classify(prev, cur, SelfWatchOptions{
		ElevatedThreshold: 0.05, CriticalThreshold: 0.2,
	})
	if level != LevelCritical {
		t.Errorf("20 %% drop classified as %v, want CRITICAL", level)
	}
}

func TestClassify_DefaultsApplyOnZero(t *testing.T) {
	t.Parallel()
	prev := telemetry.Snapshot{}
	cur := telemetry.Snapshot{EventsProduced: 1000, EventsDropped: 100}
	// Zero-value options: defaults are 0.05 / 0.20. 10 % ⇒ ELEVATED.
	level, _ := classify(prev, cur, SelfWatchOptions{})
	if level != LevelElevated {
		t.Errorf("10 %% with default thresholds classified as %v, want ELEVATED", level)
	}
}
