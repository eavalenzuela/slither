package enricher

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeTempFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sha256Hex(body []byte) string {
	s := sha256.Sum256(body)
	return hex.EncodeToString(s[:])
}

func TestHasherComputesAndCaches(t *testing.T) {
	h := newHasher(2)
	defer h.Close()

	body := []byte("hello, sha world\n")
	path := writeTempFile(t, "bin", body)
	want := sha256Hex(body)

	ch, cached, _ := h.Submit(path)
	if cached {
		t.Fatal("first Submit reports cached hit")
	}
	select {
	case got := <-ch:
		if got != want {
			t.Errorf("hash = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not complete within 2s")
	}

	// Second submit hits the cache synchronously.
	ch2, cached2, hash2 := h.Submit(path)
	if !cached2 {
		t.Fatal("second Submit missed cache")
	}
	if ch2 != nil {
		t.Fatal("cached Submit must not return a channel")
	}
	if hash2 != want {
		t.Errorf("cached hash = %q, want %q", hash2, want)
	}
}

func TestHasherCoalescesConcurrentSubmits(t *testing.T) {
	h := newHasher(1)
	defer h.Close()

	body := []byte("coalesce me")
	path := writeTempFile(t, "bin", body)
	want := sha256Hex(body)

	const N = 8
	var wg sync.WaitGroup
	results := make([]string, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch, cached, hash := h.Submit(path)
			if cached {
				results[i] = hash
				return
			}
			select {
			case r := <-ch:
				results[i] = r
			case <-time.After(2 * time.Second):
				results[i] = "<timeout>"
			}
		}(i)
	}
	wg.Wait()
	for i, got := range results {
		if got != want {
			t.Errorf("worker %d got %q, want %q", i, got, want)
		}
	}
}

func TestHasherStatFailureReturnsNilChan(t *testing.T) {
	h := newHasher(1)
	defer h.Close()
	ch, cached, hash := h.Submit("/definitely/not/a/real/path/zzz")
	if ch != nil || cached || hash != "" {
		t.Errorf("unexpected result: ch=%v cached=%v hash=%q", ch, cached, hash)
	}
}

func TestHasherFreshMtimeInvalidatesCache(t *testing.T) {
	h := newHasher(1)
	defer h.Close()

	path := writeTempFile(t, "bin", []byte("v1"))
	_, _, _ = h.Submit(path)
	// Drain first result.
	ch, _, _ := h.Submit(path)
	if ch != nil {
		<-ch
	}

	// Rewrite with different content + advance mtime so the key changes.
	if err := os.WriteFile(path, []byte("v2-longer-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	want := sha256Hex([]byte("v2-longer-body"))
	ch2, cached, _ := h.Submit(path)
	if cached {
		t.Fatal("mtime-bumped rewrite hit the cache")
	}
	select {
	case got := <-ch2:
		if got != want {
			t.Errorf("hash after rewrite = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rewrite hash timed out")
	}
}
