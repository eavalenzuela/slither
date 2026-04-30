// Phase 4 #84: per-host response-policy push.
//
// PolicyHub is the response-side analogue of control.Hub. It loads
// host_response_policies from pg, fans the latest snapshot per host
// out to subscribed sessions, and refreshes on a NOTIFY signal from
// the policies-changed trigger (mirrors RuleSource → Hub.Refresh).
//
// Wire shape:
//
//   - On Session open, Subscribe(hostID) returns a capacity-1 channel
//     pre-loaded with the host's current pb.HostPolicy. The agent
//     consumes it in its sink's send loop and writes it into an
//     atomic pointer the AutoResponder's PolicyProvider reads.
//   - On policy edit, Refresh() rebuilds the per-host map and pushes
//     the (possibly-changed) value to each affected subscriber.
//     Drop-stale: a slow subscriber sees only the latest value.
//
// A host with no row in host_response_policies receives the all-false
// detect-only baseline so a fresh enrolment is safe by default.

package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// PolicySource lists every host's response policy. *pg.Store
// satisfies it via ListHostPolicies.
type PolicySource interface {
	ListHostPolicies(ctx context.Context) ([]pg.HostPolicy, error)
}

// PolicyHub broadcasts pb.HostPolicy snapshots to per-host sessions.
// Safe for concurrent Refresh + Subscribe + Unsubscribe.
type PolicyHub struct {
	src   PolicySource
	telem *telemetry.Counters

	mu      sync.Mutex
	current map[string]*pb.HostPolicy // host_id → latest snapshot
	subs    map[string]chan *pb.HostPolicy
	version uint64
}

// NewPolicyHub constructs a PolicyHub. src is required; telem may be
// nil and gets a fresh counters value.
func NewPolicyHub(src PolicySource, telem *telemetry.Counters) *PolicyHub {
	if src == nil {
		panic("control.NewPolicyHub: nil policy source")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &PolicyHub{
		src:     src,
		telem:   telem,
		current: make(map[string]*pb.HostPolicy),
		subs:    make(map[string]chan *pb.HostPolicy),
	}
}

// Refresh re-reads ListHostPolicies, rebuilds the per-host snapshot
// map, and pushes the latest value to every subscribed host.
func (h *PolicyHub) Refresh(ctx context.Context) error {
	rows, err := h.src.ListHostPolicies(ctx)
	if err != nil {
		return fmt.Errorf("control.PolicyHub.Refresh: list: %w", err)
	}

	h.mu.Lock()
	h.version++
	version := fmt.Sprintf("%d", h.version)
	next := make(map[string]*pb.HostPolicy, len(rows))
	for _, r := range rows {
		next[r.HostID] = &pb.HostPolicy{
			AllowKillProcess: r.AllowKillProcess,
			AllowKillTree:    r.AllowKillTree,
			AllowQuarantine:  r.AllowQuarantine,
			AllowIsolate:     r.AllowIsolate,
			AllowCollect:     r.AllowCollect,
			Version:          version,
		}
	}
	h.current = next
	// Snapshot subs + their hostIDs to avoid holding the mutex while
	// pushing.
	type fanout struct {
		ch     chan *pb.HostPolicy
		hostID string
	}
	out := make([]fanout, 0, len(h.subs))
	for hostID, ch := range h.subs {
		out = append(out, fanout{ch: ch, hostID: hostID})
	}
	h.mu.Unlock()

	for _, f := range out {
		policy := next[f.hostID]
		if policy == nil {
			policy = &pb.HostPolicy{Version: version} // detect-only baseline
		}
		h.publishOne(f.ch, policy)
	}
	slog.Info("policy hub: refreshed",
		"host_count", len(next), "subscribers", len(out), "version", version)
	return nil
}

// Subscribe attaches a per-host subscriber. The returned channel has
// capacity 1; the current snapshot for hostID (or the all-false
// baseline) is delivered synchronously before return so a freshly-
// connected agent converges without an extra round-trip.
//
// Re-subscribing the same hostID closes the previous channel and
// installs a new one — duplicate sessions for one host are an
// enrolment violation, not a hub concern.
func (h *PolicyHub) Subscribe(hostID string) (updates <-chan *pb.HostPolicy, unsubscribe func()) {
	ch := make(chan *pb.HostPolicy, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.subs[hostID]; ok {
		close(old)
	}
	h.subs[hostID] = ch
	current := h.current[hostID]
	if current == nil {
		current = &pb.HostPolicy{Version: fmt.Sprintf("%d", h.version)}
	}
	ch <- current
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if cur, ok := h.subs[hostID]; ok && cur == ch {
			close(cur)
			delete(h.subs, hostID)
		}
	}
}

// Current returns the latest snapshot for hostID, or nil if no
// snapshot has been built yet (Refresh hasn't run). Used by the
// console for read-only diagnostics.
func (h *PolicyHub) Current(hostID string) *pb.HostPolicy {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current[hostID]
}

// publishOne is the same drop-stale fanout shape as Hub.publishOne —
// drain any pending value, then offer the new one without blocking.
func (h *PolicyHub) publishOne(ch chan *pb.HostPolicy, p *pb.HostPolicy) {
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- p:
	default:
	}
}

// ensure errors import survives any future signature simplification.
var _ = errors.Is
