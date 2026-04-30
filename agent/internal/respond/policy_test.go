package respond

import (
	"sync"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestPolicyCache_GetEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	c := NewPolicyCache()
	if c.Get() != nil {
		t.Error("empty cache should return nil")
	}
}

func TestPolicyCache_SetAndGet(t *testing.T) {
	t.Parallel()
	c := NewPolicyCache()
	want := &pb.HostPolicy{AllowKillProcess: true, Version: "v7"}
	c.Set(want)
	got := c.Get()
	if got != want {
		t.Errorf("Get = %p, want %p (round-trip)", got, want)
	}
	if !got.GetAllowKillProcess() || got.GetVersion() != "v7" {
		t.Errorf("Get = %+v, want round-trip", got)
	}
}

func TestPolicyCache_Provider(t *testing.T) {
	t.Parallel()
	c := NewPolicyCache()
	c.Set(&pb.HostPolicy{AllowQuarantine: true})
	if !c.Provider()().GetAllowQuarantine() {
		t.Error("Provider closure didn't read from cache")
	}
}

func TestPolicyCache_NilSafe(t *testing.T) {
	t.Parallel()
	var c *PolicyCache
	if c.Get() != nil {
		t.Error("nil cache Get should return nil")
	}
	// Set on nil receiver should not panic.
	c.Set(&pb.HostPolicy{})
}

func TestPolicyCache_ConcurrentSetGet(t *testing.T) {
	t.Parallel()
	c := NewPolicyCache()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.Set(&pb.HostPolicy{AllowKillProcess: i%2 == 0})
				_ = c.Get()
			}
		}(i)
	}
	wg.Wait()
	// No panics + race detector clean is the assertion.
}
