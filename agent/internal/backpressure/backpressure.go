// Package backpressure is the agent-side cache + sampling-decision
// surface for the Phase 5 #97 end-to-end backpressure signal.
//
// Two pressure inputs:
//
//  1. Server-pushed BackpressureSignal — the server's CH writer fell
//     behind. The Sink's handleServerMessage updates this cache;
//     collectors consult it via ShouldSample.
//
//  2. Agent self-pressure — the sink's outbound queue is dropping
//     events faster than some threshold. A goroutine in app.Run
//     polls telemetry counters every few seconds and sets the
//     cache accordingly. This catches the case where the server
//     hasn't (yet) seen the agent's drops because the connection
//     itself is the bottleneck.
//
// The two inputs collapse into a single pressure level via a max
// merge — whichever is higher wins. Stale signals (older than
// ttl, default 5min) decay back to NORMAL automatically.
//
// Sampling policy (consulted via ShouldSample):
//
//	NORMAL      → keep everything
//	ELEVATED    → drop ~50% of low-priority classes (NetworkActivity
//	              events that don't carry IOC hits;
//	              FileSystemActivity events on non-rule paths).
//	              Process events + detection findings + heartbeats
//	              + response results always pass.
//	CRITICAL    → drop ~90% of the same low-priority classes.
//
// The split between low-priority and high-priority is principled:
// process exec/exit + detection findings carry the most operator
// signal, response results carry forensic chain integrity, and
// heartbeats are tiny. Network + file events are voluminous and
// most of them are background noise — exactly the right thing to
// shed first.
package backpressure

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Level mirrors pb.BackpressureSignal_Level but kept Go-native so
// callers don't have to depend on proto enum literals.
type Level int

const (
	LevelNormal Level = iota
	LevelElevated
	LevelCritical
)

func (l Level) String() string {
	switch l {
	case LevelNormal:
		return "NORMAL"
	case LevelElevated:
		return "ELEVATED"
	case LevelCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// ttl is how long a server signal remains in effect before being
// treated as stale (and decaying to NORMAL). Phase 5 #97 spec.
const ttl = 5 * time.Minute

// state is the immutable struct stored behind the cache's atomic
// pointer. Each update allocates a new state; readers race-free
// observe a consistent snapshot.
type state struct {
	level   Level
	since   time.Time
	source  source
	dropPct float32
}

// source records which input set the current state — useful for
// diagnostics and for letting Set callers refresh only their own
// signal without clobbering the other.
type source uint8

const (
	srcNone source = iota
	srcServer
	srcSelf
)

// Cache holds the current effective pressure. Reads via Level and
// ShouldSample take the atomic.Pointer fast path with no mutex.
// Writes lock briefly to merge server + self inputs without losing
// either.
type Cache struct {
	mu sync.Mutex
	// server + self are the latest signal from each source. They're
	// kept separately so a stale server signal doesn't suppress a
	// fresh self-signal and vice versa.
	server state
	self   state

	// merged is what readers see. Recomputed inside the lock on every
	// SetServer / SetSelf. Stored as a pointer so reads are lock-free.
	merged atomic.Pointer[state]

	// rng provides the random-keep decision in ShouldSample. Caller
	// can override for deterministic tests.
	rng func() float32
	now func() time.Time
}

// New constructs a Cache. The default rng is package-internal +
// fine for production; tests override via NewWithClock.
func New() *Cache {
	c := &Cache{rng: defaultRng, now: time.Now}
	initial := state{level: LevelNormal}
	c.merged.Store(&initial)
	return c
}

// NewWithClock returns a Cache with deterministic rng + clock for
// tests. rng must return a value in [0,1).
func NewWithClock(rng func() float32, now func() time.Time) *Cache {
	c := &Cache{rng: rng, now: now}
	initial := state{level: LevelNormal}
	c.merged.Store(&initial)
	return c
}

// SetServer updates the server-pushed signal. The merged level
// becomes max(server, self) after each update. Caller passes the
// proto enum from the wire.
func (c *Cache) SetServer(level pb.BackpressureSignal_Level, dropPct float32, since time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.server = state{
		level:   levelFromProto(level),
		since:   since,
		source:  srcServer,
		dropPct: dropPct,
	}
	c.recomputeLocked()
}

// SetSelf updates the agent-self-pressure signal. Called by the
// app's drop-rate watcher.
func (c *Cache) SetSelf(level Level, dropPct float32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.self = state{
		level:   level,
		since:   c.now(),
		source:  srcSelf,
		dropPct: dropPct,
	}
	c.recomputeLocked()
}

// recomputeLocked picks the max-level state, expiring stale inputs.
// Caller holds c.mu.
func (c *Cache) recomputeLocked() {
	now := c.now()
	pickServer := c.server
	if !c.server.since.IsZero() && now.Sub(c.server.since) > ttl {
		pickServer = state{level: LevelNormal}
	}
	pickSelf := c.self
	if !c.self.since.IsZero() && now.Sub(c.self.since) > ttl {
		pickSelf = state{level: LevelNormal}
	}
	winner := pickServer
	if pickSelf.level > winner.level {
		winner = pickSelf
	}
	c.merged.Store(&winner)
}

// Level returns the current effective pressure. Lock-free.
func (c *Cache) Level() Level {
	if c == nil {
		return LevelNormal
	}
	s := c.merged.Load()
	if s == nil {
		return LevelNormal
	}
	// Decay-on-read: the lock-free reader can't expire the cache,
	// but it can fall back to NORMAL when the stored state is past
	// ttl. The next SetServer/SetSelf call will permanently rewrite
	// the merged pointer.
	if !s.since.IsZero() && c.now().Sub(s.since) > ttl {
		return LevelNormal
	}
	return s.level
}

// ShouldSample reports whether an event of the given OCSF class
// should be kept. true = pass to the next stage, false = drop.
//
// Process + detection events always pass — they carry the highest
// operator signal. Network + file events are sampled down per the
// current pressure level. Heartbeats and response results don't
// flow through this path.
func (c *Cache) ShouldSample(class ocsf.ClassID) bool {
	if c == nil {
		return true
	}
	level := c.Level()
	if level == LevelNormal {
		return true
	}
	if !isLowPriority(class) {
		return true
	}
	keep := keepFraction(level)
	return c.rng() < keep
}

// keepFraction is the fraction of low-priority events to keep at
// each pressure level. Critical drops more aggressively than
// elevated; both leave at least 10% to preserve sampled ground
// truth for post-mortems.
func keepFraction(l Level) float32 {
	switch l {
	case LevelElevated:
		return 0.5
	case LevelCritical:
		return 0.1
	}
	return 1.0
}

// isLowPriority returns true for OCSF classes we shed under load.
// Process activity (1007) is high-priority; detection findings (2004)
// are high-priority. Network activity (4001) and file_system_activity
// (1001) are voluminous and most of their events are background
// noise — exactly the right thing to drop first.
func isLowPriority(class ocsf.ClassID) bool {
	switch class {
	case ocsf.ClassNetworkActivity, ocsf.ClassFileSystemActivity:
		return true
	}
	return false
}

// levelFromProto maps the wire enum to the Go-native Level.
// Unspecified collapses to NORMAL.
func levelFromProto(l pb.BackpressureSignal_Level) Level {
	switch l {
	case pb.BackpressureSignal_LEVEL_NORMAL:
		return LevelNormal
	case pb.BackpressureSignal_LEVEL_ELEVATED:
		return LevelElevated
	case pb.BackpressureSignal_LEVEL_CRITICAL:
		return LevelCritical
	}
	return LevelNormal
}
