package backpressure

import (
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestCache_DefaultLevelIsNormal(t *testing.T) {
	t.Parallel()
	c := New()
	if c.Level() != LevelNormal {
		t.Errorf("default Level = %v, want NORMAL", c.Level())
	}
	// All classes pass under NORMAL.
	if !c.ShouldSample(ocsf.ClassNetworkActivity) {
		t.Error("NORMAL should keep NetworkActivity")
	}
	if !c.ShouldSample(ocsf.ClassProcessActivity) {
		t.Error("NORMAL should keep ProcessActivity")
	}
}

func TestCache_NilSafe(t *testing.T) {
	t.Parallel()
	var c *Cache
	if c.Level() != LevelNormal {
		t.Errorf("nil Cache.Level = %v, want NORMAL", c.Level())
	}
	if !c.ShouldSample(ocsf.ClassNetworkActivity) {
		t.Error("nil Cache.ShouldSample = false, want true (no-op)")
	}
}

func TestCache_ServerSignalElevatesLevel(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetServer(pb.BackpressureSignal_LEVEL_CRITICAL, 0.85, time.Now())
	if c.Level() != LevelCritical {
		t.Errorf("Level = %v, want CRITICAL after server CRITICAL", c.Level())
	}
}

func TestCache_HighPriorityClassesAlwaysPass(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetServer(pb.BackpressureSignal_LEVEL_CRITICAL, 0.99, time.Now())
	for _, class := range []ocsf.ClassID{
		ocsf.ClassProcessActivity,
		ocsf.ClassDetectionFinding,
	} {
		if !c.ShouldSample(class) {
			t.Errorf("CRITICAL pressure should still keep %v (high priority)", class)
		}
	}
}

func TestCache_LowPriorityDropFractionMatchesLevel(t *testing.T) {
	t.Parallel()
	// Deterministic rng: returns 0.0, 0.4, 0.51, 0.95 in order.
	values := []float32{0.0, 0.4, 0.51, 0.95}
	idx := 0
	rng := func() float32 {
		v := values[idx%len(values)]
		idx++
		return v
	}
	c := NewWithClock(rng, time.Now)

	// At ELEVATED (keep=0.5): rng < 0.5 keeps. So 0.0, 0.4 keep; 0.51, 0.95 drop.
	c.SetServer(pb.BackpressureSignal_LEVEL_ELEVATED, 0.5, time.Now())
	wants := []bool{true, true, false, false}
	for i, want := range wants {
		got := c.ShouldSample(ocsf.ClassNetworkActivity)
		if got != want {
			t.Errorf("ELEVATED rng-call %d (val=%v): got %v, want %v", i, values[i], got, want)
		}
	}

	// Reset rng index for the next round.
	idx = 0

	// At CRITICAL (keep=0.1): only 0.0 keeps; rest drop.
	c.SetServer(pb.BackpressureSignal_LEVEL_CRITICAL, 0.9, time.Now())
	wants = []bool{true, false, false, false}
	for i, want := range wants {
		got := c.ShouldSample(ocsf.ClassNetworkActivity)
		if got != want {
			t.Errorf("CRITICAL rng-call %d (val=%v): got %v, want %v", i, values[i], got, want)
		}
	}
}

func TestCache_SelfSignalElevatesIndependently(t *testing.T) {
	t.Parallel()
	c := New()
	// No server signal yet — self alone elevates the cache.
	c.SetSelf(LevelElevated, 0.2)
	if c.Level() != LevelElevated {
		t.Errorf("Level = %v after self ELEVATED, want ELEVATED", c.Level())
	}
}

func TestCache_MaxMergeBetweenServerAndSelf(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetServer(pb.BackpressureSignal_LEVEL_ELEVATED, 0.4, time.Now())
	c.SetSelf(LevelCritical, 0.6)
	if c.Level() != LevelCritical {
		t.Errorf("Level = %v, want CRITICAL (max of server=ELEVATED, self=CRITICAL)", c.Level())
	}
	// Server can't downgrade self.
	c.SetServer(pb.BackpressureSignal_LEVEL_NORMAL, 0.0, time.Now())
	if c.Level() != LevelCritical {
		t.Errorf("Level = %v after server NORMAL, want CRITICAL still (self holds)", c.Level())
	}
}

func TestCache_StaleSignalsDecayToNormal(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	rng := func() float32 { return 0 }
	now := func() time.Time { return clock }
	c := NewWithClock(rng, now)

	c.SetServer(pb.BackpressureSignal_LEVEL_CRITICAL, 0.9, clock)
	if c.Level() != LevelCritical {
		t.Fatal("expected CRITICAL")
	}
	// Advance past TTL.
	clock = clock.Add(ttl + time.Second)
	if c.Level() != LevelNormal {
		t.Errorf("Level after %v elapsed = %v, want NORMAL (decayed)", ttl, c.Level())
	}
}

func TestCache_ConcurrentReadsAndWrites(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.SetServer(pb.BackpressureSignal_LEVEL_ELEVATED, 0.3, time.Now())
				_ = c.Level()
				_ = c.ShouldSample(ocsf.ClassNetworkActivity)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.SetSelf(LevelCritical, 0.7)
				_ = c.Level()
			}
		}()
	}
	wg.Wait()
}

func TestKeepFractionMonotone(t *testing.T) {
	t.Parallel()
	if keepFraction(LevelNormal) <= keepFraction(LevelElevated) {
		t.Error("keepFraction(NORMAL) should exceed ELEVATED")
	}
	if keepFraction(LevelElevated) <= keepFraction(LevelCritical) {
		t.Error("keepFraction(ELEVATED) should exceed CRITICAL")
	}
	if keepFraction(LevelCritical) < 0.05 || keepFraction(LevelCritical) > 0.5 {
		t.Errorf("keepFraction(CRITICAL) = %v out of bounds", keepFraction(LevelCritical))
	}
}
