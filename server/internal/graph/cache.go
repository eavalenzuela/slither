package graph

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Cache stores rendered SVG bytes keyed by an opaque string.
//
// Two tiers: a bounded in-memory LRU on top of an on-disk LRU. The
// disk tier survives restarts and bounds occupancy on the volume the
// systemd unit's StateDirectory points at; the memory tier short-
// circuits the disk read on the hot path (alert detail re-loads,
// repeated /alerts/{id}/graph.svg fetches by the same operator).
//
// SVG output for one detection-flow graph is a few hundred kB at most,
// so a small mem cap covers the working set without blowing the
// resident-set budget.
type Cache struct {
	dir          string
	memCap       int
	diskCapBytes int64

	mu        sync.Mutex
	mem       map[string]*list.Element
	memOrder  *list.List // front = most recent
	disk      map[string]*diskEntry
	diskTotal int64
}

type memEntry struct {
	key string
	svg []byte
}

type diskEntry struct {
	size int64
	key  string
}

// CacheOptions configures NewCache. Zero values fall back to documented
// defaults so callers without strong preferences just supply Dir.
type CacheOptions struct {
	Dir          string
	MemEntries   int   // default 32
	DiskCapBytes int64 // default 256 MiB
}

// NewCache creates a Cache rooted at opts.Dir, populating in-memory
// metadata about any pre-existing files under that directory so the
// disk LRU continues across restarts. Files with non-hex names are
// ignored (disk entries are keyed on hex digests).
func NewCache(opts CacheOptions) (*Cache, error) {
	if opts.Dir == "" {
		return nil, errors.New("graph.NewCache: empty dir")
	}
	if opts.MemEntries <= 0 {
		opts.MemEntries = 32
	}
	if opts.DiskCapBytes <= 0 {
		opts.DiskCapBytes = 256 * 1024 * 1024
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("graph.NewCache: mkdir %q: %w", opts.Dir, err)
	}

	c := &Cache{
		dir:          opts.Dir,
		memCap:       opts.MemEntries,
		diskCapBytes: opts.DiskCapBytes,
		mem:          make(map[string]*list.Element),
		memOrder:     list.New(),
		disk:         make(map[string]*diskEntry),
	}
	if err := c.loadDisk(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadDisk scans the cache directory and seeds disk metadata. Existing
// files are kept; load order is by mtime ascending so the oldest file
// becomes the eviction candidate.
func (c *Cache) loadDisk() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("graph.NewCache: read dir: %w", err)
	}
	type stat struct {
		key  string
		size int64
		mod  int64
	}
	stats := make([]stat, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isCacheFile(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		stats = append(stats, stat{
			key:  keyFromFilename(name),
			size: info.Size(),
			mod:  info.ModTime().UnixNano(),
		})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].mod < stats[j].mod })
	c.disk = make(map[string]*diskEntry, len(stats))
	c.diskTotal = 0
	for _, s := range stats {
		c.disk[s.key] = &diskEntry{size: s.size, key: s.key}
		c.diskTotal += s.size
	}
	// Trim if existing files already exceed the cap (operator could
	// have shrunk DiskCapBytes between restarts).
	c.evictDiskLocked()
	return nil
}

// Key derives a stable cache key from the alert id and the alert's
// event_ids. Keys are hex sha-256 so they double as filenames without
// further escaping.
//
// event_ids are sorted before hashing so the order in which the alert
// row stored them doesn't change the key. Spec calls for invalidation
// when event_ids change — sorted hash gives that exact property.
func Key(alertID string, eventIDs []string) string {
	sorted := append([]string(nil), eventIDs...)
	sort.Strings(sorted)
	h := sha256.New()
	_, _ = io.WriteString(h, alertID)
	_, _ = io.WriteString(h, "|")
	for i, e := range sorted {
		if i > 0 {
			_, _ = io.WriteString(h, ",")
		}
		_, _ = io.WriteString(h, e)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached SVG for key, or (nil, false) on miss. Hits in
// either tier promote the entry to most-recently-used in the memory
// LRU; disk hits are also re-stamped (mtime touch) so the disk LRU
// reflects access.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.mem[key]; ok {
		c.memOrder.MoveToFront(elem)
		entry, _ := elem.Value.(*memEntry)
		return append([]byte(nil), entry.svg...), true
	}

	if _, ok := c.disk[key]; ok {
		path := c.pathFor(key)
		data, err := os.ReadFile(path) //nolint:gosec // operator-rooted dir
		if err == nil {
			c.touchDiskLocked(key)
			c.putMemLocked(key, data)
			return append([]byte(nil), data...), true
		}
		// Stale metadata — file vanished out from under us. Drop the
		// entry and treat as miss.
		delete(c.disk, key)
	}
	return nil, false
}

// Put writes svg under key into both tiers. Disk write happens
// best-effort: an IO error returns the error but does not roll back
// the in-memory entry — operators get a working graph this request,
// and the next restart drops the entry cleanly when the file isn't
// found.
func (c *Cache) Put(key string, svg []byte) error {
	if key == "" {
		return errors.New("graph.Cache.Put: empty key")
	}
	if len(svg) == 0 {
		return errors.New("graph.Cache.Put: empty svg")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.putMemLocked(key, svg)

	path := c.pathFor(key)
	if err := writeFileAtomic(path, svg); err != nil {
		return fmt.Errorf("graph.Cache.Put: write %q: %w", path, err)
	}
	if existing, ok := c.disk[key]; ok {
		c.diskTotal -= existing.size
	}
	c.disk[key] = &diskEntry{size: int64(len(svg)), key: key}
	c.diskTotal += int64(len(svg))
	c.evictDiskLocked()
	return nil
}

// Invalidate drops the entry from both tiers. Useful when the caller
// knows the underlying inputs (event_ids) have changed and a stale
// SVG would mislead.
func (c *Cache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.mem[key]; ok {
		c.memOrder.Remove(elem)
		delete(c.mem, key)
	}
	if existing, ok := c.disk[key]; ok {
		c.diskTotal -= existing.size
		delete(c.disk, key)
	}
	_ = os.Remove(c.pathFor(key))
}

func (c *Cache) putMemLocked(key string, svg []byte) {
	if elem, ok := c.mem[key]; ok {
		entry, _ := elem.Value.(*memEntry)
		entry.svg = append([]byte(nil), svg...)
		c.memOrder.MoveToFront(elem)
		return
	}
	entry := &memEntry{key: key, svg: append([]byte(nil), svg...)}
	elem := c.memOrder.PushFront(entry)
	c.mem[key] = elem
	for c.memOrder.Len() > c.memCap {
		oldest := c.memOrder.Back()
		if oldest == nil {
			break
		}
		c.memOrder.Remove(oldest)
		oldestEntry, _ := oldest.Value.(*memEntry)
		delete(c.mem, oldestEntry.key)
	}
}

func (c *Cache) touchDiskLocked(key string) {
	// Best-effort mtime touch so a future restart's mtime-sorted load
	// preserves recent-access ordering.
	_ = os.Chtimes(c.pathFor(key), nowFn(), nowFn())
}

func (c *Cache) evictDiskLocked() {
	if c.diskTotal <= c.diskCapBytes {
		return
	}
	type sortable struct {
		key string
		mod int64
	}
	all := make([]sortable, 0, len(c.disk))
	for k := range c.disk {
		info, err := os.Stat(c.pathFor(k))
		if err != nil {
			delete(c.disk, k)
			continue
		}
		all = append(all, sortable{key: k, mod: info.ModTime().UnixNano()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod < all[j].mod })
	for _, s := range all {
		if c.diskTotal <= c.diskCapBytes {
			break
		}
		entry, ok := c.disk[s.key]
		if !ok {
			continue
		}
		c.diskTotal -= entry.size
		delete(c.disk, s.key)
		_ = os.Remove(c.pathFor(s.key))
	}
}

func (c *Cache) pathFor(key string) string {
	return filepath.Join(c.dir, key+".svg")
}

func isCacheFile(name string) bool {
	if filepath.Ext(name) != ".svg" {
		return false
	}
	stem := name[:len(name)-len(".svg")]
	if len(stem) != sha256.Size*2 {
		return false
	}
	for _, r := range stem {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			continue
		default:
			return false
		}
	}
	return true
}

func keyFromFilename(name string) string {
	return name[:len(name)-len(".svg")]
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "graph-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
