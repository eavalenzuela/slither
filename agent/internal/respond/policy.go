// Phase 4 #84: agent-side host-policy cache.
//
// PolicyCache holds the latest pb.HostPolicy received from the
// server's ServerMessage.host_policy push. Stored behind
// atomic.Pointer so the AutoResponder's hot path (#83) reads
// lock-free.
//
// nil pointer = "no policy seen yet" → detect-only baseline (matches
// pg.HostPolicy zero-value semantics on the server side).

package respond

import (
	"sync/atomic"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// PolicyCache wraps an atomic.Pointer[*pb.HostPolicy]. Methods are
// safe to call from any goroutine.
type PolicyCache struct {
	v atomic.Pointer[pb.HostPolicy]
}

// NewPolicyCache constructs an empty cache. Initial Get() returns nil
// until the first Set call — which the gRPC sink does on the first
// HostPolicy push (the server delivers the snapshot synchronously on
// session open).
func NewPolicyCache() *PolicyCache {
	return &PolicyCache{}
}

// Set replaces the cached policy. Concurrent with Get; readers see
// either the old or the new pointer atomically.
func (c *PolicyCache) Set(p *pb.HostPolicy) {
	if c == nil {
		return
	}
	c.v.Store(p)
}

// Get returns the latest policy or nil if none has been received.
// AutoResponder's PolicyProvider wraps this.
func (c *PolicyCache) Get() *pb.HostPolicy {
	if c == nil {
		return nil
	}
	return c.v.Load()
}

// Provider returns a PolicyProvider closure that reads from this
// cache. The closure is the production hookup for
// NewAutoResponder(executor, cache.Provider()).
func (c *PolicyCache) Provider() PolicyProvider {
	return c.Get
}
