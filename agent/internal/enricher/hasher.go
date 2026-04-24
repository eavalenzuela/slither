package enricher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"syscall"
)

// hashKey identifies the content of a file by filesystem identity plus mtime,
// so two processes execing the same binary resolve to the same cached hash and
// an overwrite-in-place produces a fresh one.
type hashKey struct {
	dev   uint64
	inode uint64
	mtime int64
}

// hasher is a bounded worker pool that computes SHA-256 of executables off the
// enrichment hot path. Results are cached by hashKey; concurrent submitters
// for the same key share a single in-flight computation.
type hasher struct {
	workers int
	jobCh   chan hashJob

	mu      sync.Mutex
	cache   map[hashKey]string
	pending map[hashKey][]chan string

	wg     sync.WaitGroup
	stop   chan struct{}
	closed bool
}

type hashJob struct {
	path string
	key  hashKey
}

func newHasher(workers int) *hasher {
	if workers <= 0 {
		workers = 4
	}
	h := &hasher{
		workers: workers,
		jobCh:   make(chan hashJob, workers*4),
		cache:   make(map[hashKey]string),
		pending: make(map[hashKey][]chan string),
		stop:    make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		h.wg.Add(1)
		go h.worker()
	}
	return h
}

// Start is a no-op — workers start at construction. Kept as a seam for a
// future lazy variant if the enricher ever needs to pause/resume hashing.
func (h *hasher) Start(context.Context) {}

// Close drains in-flight work and releases the worker goroutines. Safe to
// call multiple times.
func (h *hasher) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	close(h.jobCh)
	h.mu.Unlock()
	h.wg.Wait()
}

// Submit asks the pool to hash path. If the file's identity is already in the
// cache, returns (nil, true, hash) for immediate inline attachment. Otherwise
// returns a receive-only channel that yields exactly one value (the hex hash
// on success, "" on failure) when the worker finishes — and closes after.
//
// Concurrent submitters for the same key share one in-flight computation;
// every subscriber gets its own channel.
func (h *hasher) Submit(path string) (result <-chan string, cached bool, cachedHash string) {
	key, ok := statKey(path)
	if !ok {
		return nil, false, ""
	}

	h.mu.Lock()
	if hash, cached := h.cache[key]; cached {
		h.mu.Unlock()
		return nil, true, hash
	}
	ch := make(chan string, 1)
	if subs, inFlight := h.pending[key]; inFlight {
		h.pending[key] = append(subs, ch)
		h.mu.Unlock()
		return ch, false, ""
	}
	h.pending[key] = []chan string{ch}
	closed := h.closed
	h.mu.Unlock()

	if closed {
		ch <- ""
		close(ch)
		return ch, false, ""
	}

	select {
	case h.jobCh <- hashJob{path: path, key: key}:
	default:
		// Pool is saturated. Rather than block the enricher, fail this
		// submission back immediately — caller will emit without hash.
		h.failPending(key)
	}
	return ch, false, ""
}

func (h *hasher) worker() {
	defer h.wg.Done()
	for job := range h.jobCh {
		hash := sha256File(job.path)
		h.complete(job.key, hash)
	}
}

// complete finalises a job: populate the cache (only on success, so a
// transient read error doesn't poison subsequent attempts at the same path)
// and notify every subscriber.
func (h *hasher) complete(key hashKey, hash string) {
	h.mu.Lock()
	subs := h.pending[key]
	delete(h.pending, key)
	if hash != "" {
		h.cache[key] = hash
	}
	h.mu.Unlock()

	for _, ch := range subs {
		ch <- hash
		close(ch)
	}
}

// failPending is used when the job queue rejects enqueue. Notify subscribers
// with the empty string so they fall through to the no-hash path.
func (h *hasher) failPending(key hashKey) {
	h.mu.Lock()
	subs := h.pending[key]
	delete(h.pending, key)
	h.mu.Unlock()
	for _, ch := range subs {
		ch <- ""
		close(ch)
	}
}

// statKey stats path and derives the cache key. Symlinks are followed so the
// key identifies the resolved file, not the link.
func statKey(path string) (hashKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return hashKey{}, false
	}
	return hashKey{
		dev:   st.Dev,
		inode: st.Ino,
		mtime: st.Mtim.Nano(),
	}, true
}

// sha256File streams the file through a SHA-256 hasher. Returns "" on any I/O
// error — the caller treats that as "no hash available" and continues.
func sha256File(path string) string {
	f, err := os.Open(path) //nolint:gosec // G304: hashing an operator-controlled exec path is the whole point
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
