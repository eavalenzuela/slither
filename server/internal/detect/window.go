package detect

import (
	"strings"
	"sync"
	"time"
)

// hit is one matched event recorded under a group key inside a
// ruleWindow. We retain the contributing event_id so a fired Finding
// can reference the events that composed the aggregation.
type hit struct {
	at      time.Time
	eventID string
	hostID  string
}

// ruleWindow is the bounded sliding window for a single server-only
// rule. Per ADR-0018 it caps both the per-key timestamp ring and the
// number of distinct keys; over-cap inserts evict the LRU key and bump
// the engine's WindowEvictions counter. The lock granularity is the
// whole rule — we never hold it longer than a single trim+append, and
// the detection engine runs sequentially per event so contention is
// dominated by the (rare) sweep.
type ruleWindow struct {
	mu      sync.Mutex
	window  time.Duration
	maxKeys int
	keys    map[string]*hitRing

	// onEvict bumps the engine's per-rule eviction telemetry exactly
	// once per dropped key. Optional — tests pass nil.
	onEvict func()
}

// hitRing is a per-group-key ring of hits in ascending time order. Same
// data shape as the agent's bounded-stateful evaluator (#56) but kept
// independent so the server can evolve different policies without
// dragging the agent.
type hitRing struct {
	hits      []hit
	lastTouch int64 // for LRU when the keys map exceeds maxKeys
}

func newRuleWindow(window time.Duration, maxKeys int, onEvict func()) *ruleWindow {
	if maxKeys <= 0 {
		maxKeys = 1
	}
	return &ruleWindow{
		window:  window,
		maxKeys: maxKeys,
		keys:    make(map[string]*hitRing),
		onEvict: onEvict,
	}
}

// record appends a hit for key at now and returns the live event slice
// in the rule's window plus the count. Expired hits are trimmed from
// the head before append so callers never observe stale entries.
func (w *ruleWindow) record(now time.Time, key, eventID, hostID string) (hits []hit, count int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window).UnixNano()
	r, ok := w.keys[key]
	if !ok {
		if len(w.keys) >= w.maxKeys {
			w.evictLRULocked()
		}
		r = &hitRing{}
		w.keys[key] = r
	}
	i := 0
	for ; i < len(r.hits); i++ {
		if r.hits[i].at.UnixNano() >= cutoff {
			break
		}
	}
	if i > 0 {
		r.hits = r.hits[i:]
	}
	r.hits = append(r.hits, hit{at: now, eventID: eventID, hostID: hostID})
	r.lastTouch = now.UnixNano()
	return r.hits, len(r.hits)
}

// peek returns the live hit slice for key without recording a new one
// (used by `near` — the caller records its own side and peeks the
// counterpart's recent activity). Returns nil + 0 when the key has
// never been touched or has fully expired by now.
func (w *ruleWindow) peek(now time.Time, key string) (hits []hit, count int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r, ok := w.keys[key]
	if !ok {
		return nil, 0
	}
	cutoff := now.Add(-w.window).UnixNano()
	i := 0
	for ; i < len(r.hits); i++ {
		if r.hits[i].at.UnixNano() >= cutoff {
			break
		}
	}
	if i > 0 {
		r.hits = r.hits[i:]
	}
	return r.hits, len(r.hits)
}

// sweep prunes expired hits across every key and removes empty keys.
// Engine runs this on a coarse cadence so the hot record path only
// trims its own key.
func (w *ruleWindow) sweep(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-w.window).UnixNano()
	for k, r := range w.keys {
		i := 0
		for ; i < len(r.hits); i++ {
			if r.hits[i].at.UnixNano() >= cutoff {
				break
			}
		}
		if i > 0 {
			r.hits = r.hits[i:]
		}
		if len(r.hits) == 0 {
			delete(w.keys, k)
		}
	}
}

func (w *ruleWindow) evictLRULocked() {
	var (
		oldestKey string
		oldestT   int64
		init      bool
	)
	for k, r := range w.keys {
		if !init || r.lastTouch < oldestT {
			oldestKey = k
			oldestT = r.lastTouch
			init = true
		}
	}
	if !init {
		return
	}
	delete(w.keys, oldestKey)
	if w.onEvict != nil {
		w.onEvict()
	}
}

// joinKey is the synthetic key used in `near` rule windows: "L" for
// the left selection's matches, "R" for the right's. Picked as
// non-printable strings so they can't collide with user-supplied
// by-tuple values.
const (
	joinKeyLeft  = "\x00L"
	joinKeyRight = "\x00R"
)

// composeKey renders a multi-field by-tuple as a single map key.
// Empty fields encode as a literal "<nil>" so a rule with `by user`
// doesn't merge missing-user events with present-user-"<nil>" ones.
func composeKey(values []string) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		if values[0] == "" {
			return "<nil>"
		}
		return values[0]
	}
	parts := make([]string, len(values))
	for i, v := range values {
		if v == "" {
			parts[i] = "<nil>"
			continue
		}
		parts[i] = v
	}
	return strings.Join(parts, "\x1f")
}
