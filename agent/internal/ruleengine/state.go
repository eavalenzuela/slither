package ruleengine

import (
	"strings"
	"sync"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// ruleState is the bounded-stateful evaluator backing one rule's
// `| count() [by ...] OP N` aggregation. Per ADR-0018 it holds a ring
// of monotonic timestamps keyed by the by-tuple, capped at maxKeys
// distinct keys; over-cap inserts evict the least-recently-touched key
// and bump telemetry. Restart clears the state — Phase 3 #59's CH
// replay opt-in handles cold-start for rules that need it.
//
// All public methods are safe for concurrent use; the engine's hot
// path holds the lock only long enough to trim+append for the single
// key that just matched, while the janitor's Sweep takes the same
// lock once per tick to drop expired timestamps across every key.
type ruleState struct {
	mu        sync.Mutex
	window    time.Duration
	maxKeys   int
	op        ruleast.AggOp
	threshold int64
	by        []string
	telem     *telemetry.Counters

	keys map[string]*timestampRing // key → ring of nanosecond timestamps
}

// timestampRing is a slice of unix-nanosecond timestamps in ascending
// order (each new timestamp is appended; trimming removes the head). A
// plain slice is cheaper than a heap for the cap=1024 / N≈few-hundred
// regime ADR-0018 targets — append is amortised O(1) and the trim is
// a single slice header rewrite. The "ring" name is preserved from
// the spec; the implementation is a sliding window.
type timestampRing struct {
	timestamps []int64
	lastTouch  int64 // for LRU eviction when the rule's key cardinality exceeds maxKeys
}

// newRuleState allocates state for one stateful rule. windowSecs and
// maxKeys are the compiler-emitted ADR-0018 bounds; both must be
// positive (callers guard at construction time).
func newRuleState(agg *ruleast.Aggregation, windowSecs, maxKeys uint32, telem *telemetry.Counters) *ruleState {
	return &ruleState{
		window:    time.Duration(windowSecs) * time.Second,
		maxKeys:   int(maxKeys),
		op:        agg.Op,
		threshold: agg.Threshold,
		by:        append([]string(nil), agg.By...),
		telem:     telem,
		keys:      make(map[string]*timestampRing),
	}
}

// keyFromEvent renders the by-tuple as a single string. Empty by-list
// produces "" — a single global counter for the rule. Field absence
// is encoded as a literal "<nil>" so a rule with `by user` doesn't
// silently merge missing-user events with present-user-"<nil>" ones.
func (s *ruleState) keyFromEvent(env ruleast.Env) string {
	if len(s.by) == 0 {
		return ""
	}
	if len(s.by) == 1 {
		v, ok := env.Lookup(s.by[0])
		if !ok || len(v) == 0 {
			return "<nil>"
		}
		return v[0]
	}
	parts := make([]string, len(s.by))
	for i, f := range s.by {
		v, ok := env.Lookup(f)
		if !ok || len(v) == 0 {
			parts[i] = "<nil>"
			continue
		}
		parts[i] = v[0]
	}
	return strings.Join(parts, "\x1f") // unit separator — unlikely in field values
}

// tick records that the rule's predicate matched at now under key, then
// reports whether the per-key event count satisfies the aggregation
// comparison. When a new key would push past maxKeys, the
// least-recently-touched key is evicted and `state_evicted` ticks; a
// stale key whose timestamps have all expired is reaped opportunistically
// by the same path so eviction-pressure rules behave like fresh ones.
func (s *ruleState) tick(now time.Time, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.window).UnixNano()
	r, ok := s.keys[key]
	if !ok {
		if len(s.keys) >= s.maxKeys {
			s.evictLRULocked()
		}
		r = &timestampRing{}
		s.keys[key] = r
	}

	// Trim expired head — single slice rewrite, no allocation when in
	// place (Go reuses the backing array).
	i := 0
	for ; i < len(r.timestamps); i++ {
		if r.timestamps[i] >= cutoff {
			break
		}
	}
	if i > 0 {
		r.timestamps = r.timestamps[i:]
	}
	r.timestamps = append(r.timestamps, now.UnixNano())
	r.lastTouch = now.UnixNano()

	count := int64(len(r.timestamps))
	return aggCompare(s.op, count, s.threshold)
}

// sweep prunes expired timestamps and removes any keys whose ring is
// emptied as a result. The janitor tick calls this so the hot path
// stays focused on the one key it just touched. Holding the lock over
// the full map iteration is tolerable: the cap is 1024 keys per rule
// and the work is a single comparison per timestamp.
func (s *ruleState) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-s.window).UnixNano()
	for k, r := range s.keys {
		i := 0
		for ; i < len(r.timestamps); i++ {
			if r.timestamps[i] >= cutoff {
				break
			}
		}
		if i > 0 {
			r.timestamps = r.timestamps[i:]
		}
		if len(r.timestamps) == 0 {
			delete(s.keys, k)
		}
	}
}

// evictLRULocked removes the key whose lastTouch is oldest. Caller
// must hold s.mu. Telemetry tick fires once per evicted key — operators
// reading the DiagReport line see one eviction per dropped key, not
// one per state.tick.
func (s *ruleState) evictLRULocked() {
	var (
		oldestKey string
		oldestT   int64
		init      bool
	)
	for k, r := range s.keys {
		if !init || r.lastTouch < oldestT {
			oldestKey = k
			oldestT = r.lastTouch
			init = true
		}
	}
	if !init {
		return
	}
	delete(s.keys, oldestKey)
	if s.telem != nil {
		s.telem.IncStateEvicted()
	}
}

// aggCompare implements the comparison operator on a count vs. a
// threshold. Mirrors ruleast.AggOp; the redirection lets us evolve
// the state machine without dragging the AST type into the hot path.
func aggCompare(op ruleast.AggOp, count, threshold int64) bool {
	switch op {
	case ruleast.AggGT:
		return count > threshold
	case ruleast.AggGTE:
		return count >= threshold
	case ruleast.AggLT:
		return count < threshold
	case ruleast.AggLTE:
		return count <= threshold
	case ruleast.AggEQ:
		return count == threshold
	case ruleast.AggNE:
		return count != threshold
	}
	return false
}

// statefulRule is the surface the engine's janitor uses to find rules
// that need periodic sweeping. sigmaCompiledRule satisfies it when its
// rule carries a non-nil Aggregation; other CompiledRule implementations
// can opt in by exposing a sweep(time.Time) method.
type statefulRule interface {
	sweep(now time.Time)
}
