package enricher

import (
	"sync"
	"time"
)

// procEntry is the userspace-side projection of a process the enricher has
// observed. Exec/fork populate it; exit marks it for delayed eviction so late
// events (hash completion, out-of-order exit/exec pairs) can still resolve
// parent chains and identity fields.
type procEntry struct {
	pid       uint32
	ppid      uint32
	uid       uint32
	gid       uint32
	comm      string
	exe       string
	cmdline   string
	createdAt time.Time
	exited    bool
	exitAt    time.Time
}

// cacheShardCount is the lock-stripe fan-out. Must be a power of two so the
// shard index is a cheap mask. 64 matches ProcessWorkers default so workers
// statistically hit distinct shards on sequential stress-ng pids — keeps
// RWMutex writer-preference from queueing readers during concurrent
// upserts, which showed up as worker throughput ceiling on RHEL 10 /
// kernel 6.12 under stress-ng --exec 100 (task #15).
const cacheShardCount = 64
const cacheShardMask = cacheShardCount - 1

// procCache is a pid-keyed process cache, lock-striped across cacheShardCount
// shards. Callers observe values by copy. Contention on a single sync.RWMutex
// was the dominant enricher cost at ~9k events/s under 8 workers (task #30);
// sharding collapses it by hashing pid & mask.
type procCache struct {
	shards [cacheShardCount]cacheShard
}

type cacheShard struct {
	mu      sync.RWMutex
	entries map[uint32]*procEntry
}

func newProcCache() *procCache {
	c := &procCache{}
	for i := range c.shards {
		c.shards[i].entries = make(map[uint32]*procEntry)
	}
	return c
}

func (c *procCache) shard(pid uint32) *cacheShard {
	return &c.shards[pid&cacheShardMask]
}

// upsert merges incoming fields into any existing entry for pid. Non-zero /
// non-empty incoming fields overwrite; zero/empty fields leave existing values
// in place. A subsequent event for a pid previously marked exited resurrects
// the entry (pid recycling after eviction grace window).
func (c *procCache) upsert(in procEntry) {
	s := c.shard(in.pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.entries[in.pid]
	if !ok {
		e := in
		s.entries[in.pid] = &e
		return
	}
	if in.ppid != 0 {
		existing.ppid = in.ppid
	}
	if in.uid != 0 || in.gid != 0 {
		existing.uid = in.uid
		existing.gid = in.gid
	}
	if in.comm != "" {
		existing.comm = in.comm
	}
	if in.exe != "" {
		existing.exe = in.exe
	}
	if in.cmdline != "" {
		existing.cmdline = in.cmdline
	}
	if !in.createdAt.IsZero() && existing.createdAt.IsZero() {
		existing.createdAt = in.createdAt
	}
	existing.exited = false
	existing.exitAt = time.Time{}
}

// markExit flags the cache entry for pid as exited at t. Actual eviction is
// deferred to evictExpired so parent-chain lookups from slightly-later events
// still find the entry.
func (c *procCache) markExit(pid uint32, t time.Time) {
	s := c.shard(pid)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[pid]; ok {
		e.exited = true
		e.exitAt = t
	}
}

// get returns a copy of the entry for pid and whether it was found.
func (c *procCache) get(pid uint32) (procEntry, bool) {
	s := c.shard(pid)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[pid]
	if !ok {
		return procEntry{}, false
	}
	return *e, true
}

// evictExpired drops entries whose exit timestamp is older than now-grace.
// Shards are walked sequentially with brief per-shard locks so the sweep
// never blocks the whole cache at once.
func (c *procCache) evictExpired(now time.Time, grace time.Duration) int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for pid, e := range s.entries {
			if e.exited && now.Sub(e.exitAt) > grace {
				delete(s.entries, pid)
				n++
			}
		}
		s.mu.Unlock()
	}
	return n
}
