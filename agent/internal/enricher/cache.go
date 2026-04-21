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

// procCache is a concurrent pid-keyed process cache. Callers observe values
// by copy; internal state is protected by mu.
type procCache struct {
	mu      sync.RWMutex
	entries map[uint32]*procEntry
}

func newProcCache() *procCache {
	return &procCache{entries: make(map[uint32]*procEntry)}
}

// upsert merges incoming fields into any existing entry for pid. Non-zero /
// non-empty incoming fields overwrite; zero/empty fields leave existing values
// in place. A subsequent event for a pid previously marked exited resurrects
// the entry (pid recycling after eviction grace window).
func (c *procCache) upsert(in procEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.entries[in.pid]
	if !ok {
		e := in
		c.entries[in.pid] = &e
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[pid]; ok {
		e.exited = true
		e.exitAt = t
	}
}

// get returns a copy of the entry for pid and whether it was found.
func (c *procCache) get(pid uint32) (procEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[pid]
	if !ok {
		return procEntry{}, false
	}
	return *e, true
}

// evictExpired drops entries whose exit timestamp is older than now-grace.
func (c *procCache) evictExpired(now time.Time, grace time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for pid, e := range c.entries {
		if e.exited && now.Sub(e.exitAt) > grace {
			delete(c.entries, pid)
			n++
		}
	}
	return n
}

