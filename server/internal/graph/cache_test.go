package graph

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKey_StableAcrossEventOrdering(t *testing.T) {
	t.Parallel()
	a := Key("alert-1", []string{"e1", "e2", "e3"})
	b := Key("alert-1", []string{"e3", "e1", "e2"})
	if a != b {
		t.Fatalf("Key not order-stable: %s vs %s", a, b)
	}
}

func TestKey_DiffersOnEventChange(t *testing.T) {
	t.Parallel()
	a := Key("alert-1", []string{"e1", "e2"})
	b := Key("alert-1", []string{"e1", "e2", "e3"})
	if a == b {
		t.Fatal("Key collided across different event_ids sets")
	}
}

func TestKey_DiffersOnAlertID(t *testing.T) {
	t.Parallel()
	a := Key("alert-1", []string{"e1"})
	b := Key("alert-2", []string{"e1"})
	if a == b {
		t.Fatal("Key collided across different alert ids")
	}
}

func TestCache_PutGet(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 4, 10*1024*1024)

	key := "abc123"
	svg := []byte(`<svg/>`)
	if err := c.Put(key, svg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("Get miss after Put")
	}
	if !bytes.Equal(got, svg) {
		t.Fatalf("got %q want %q", got, svg)
	}
}

func TestCache_DiskSurvivesMemEvict(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 2, 10*1024*1024)

	for i := 0; i < 5; i++ {
		k := strings.Repeat(string(rune('a'+i)), 64)
		if err := c.Put(k, []byte("svg-"+k[:1])); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	// Oldest key should be evicted from memory but readable from disk.
	first := strings.Repeat("a", 64)
	if _, ok := c.mem[first]; ok {
		t.Fatal("expected first key evicted from in-memory LRU")
	}
	got, ok := c.Get(first)
	if !ok {
		t.Fatal("Get miss after mem eviction; expected disk hit")
	}
	if string(got) != "svg-a" {
		t.Fatalf("got %q want svg-a", got)
	}
	// After Get, key should be promoted into memory tier.
	if _, ok := c.mem[first]; !ok {
		t.Fatal("disk hit did not repopulate memory tier")
	}
}

func TestCache_DiskCapEvictsOldest(t *testing.T) {
	t.Parallel()
	// Cap small enough that a third entry forces eviction.
	c := newTestCache(t, 32, 200)

	keys := []string{
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	}
	for _, k := range keys {
		if err := c.Put(k, bytes.Repeat([]byte("x"), 90)); err != nil {
			t.Fatalf("Put %s: %v", k[:1], err)
		}
	}
	// Cap = 200 bytes, three 90-byte payloads = 270; eviction must
	// have dropped at least one disk entry.
	if c.diskTotal > 200 {
		t.Fatalf("disk total %d exceeds cap 200 after eviction", c.diskTotal)
	}
	if len(c.disk) >= 3 {
		t.Fatalf("expected at least one disk eviction, still have %d entries", len(c.disk))
	}
}

func TestCache_LoadsExistingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Pre-populate one valid + one invalid file.
	valid := strings.Repeat("d", 64) + ".svg"
	if err := os.WriteFile(filepath.Join(dir, valid), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "not-a-key.svg"), []byte("noise"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(CacheOptions{Dir: dir, MemEntries: 4, DiskCapBytes: 1024})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, ok := c.disk[strings.Repeat("d", 64)]; !ok {
		t.Fatal("valid pre-existing file missing from disk index")
	}
	if _, ok := c.disk["not-a-key"]; ok {
		t.Fatal("non-hex filename leaked into disk index")
	}
}

func TestCache_Invalidate(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 4, 10*1024*1024)

	k := strings.Repeat("e", 64)
	if err := c.Put(k, []byte("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	c.Invalidate(k)
	if _, ok := c.Get(k); ok {
		t.Fatal("Get hit after Invalidate")
	}
	if _, err := os.Stat(filepath.Join(c.dir, k+".svg")); !os.IsNotExist(err) {
		t.Fatal("disk file remained after Invalidate")
	}
}

func newTestCache(t *testing.T, memCap int, diskCap int64) *Cache {
	t.Helper()
	dir := t.TempDir()
	c, err := NewCache(CacheOptions{Dir: dir, MemEntries: memCap, DiskCapBytes: diskCap})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c
}
