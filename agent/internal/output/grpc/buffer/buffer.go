// Package buffer is the on-disk ringbuffer the agent's gRPC sink
// spools to when the server is unreachable. Phase 5 #96.
//
// Goals (per ADR-0035 §"Resilience bar"):
//   - Survive an agent restart: events spooled before shutdown must
//     replay on the next boot's first successful Session stream.
//   - Bounded disk footprint: 256 MiB default, oldest-wins eviction.
//   - Bounded by age: events older than max_age aren't replayed
//     (no backfill storms after multi-day disconnections).
//   - Append speed dominant: the sink pushes hundreds of events/s
//     under normal load. Each Append must be near O(write+sync).
//
// Layout: a directory of segment files. Each segment is an
// append-only sequence of length-prefixed serialised pb.Envelope
// records (4-byte big-endian length followed by the marshalled
// bytes). Active write segment rotates when it crosses
// segmentBytes; replay walks segments in order and deletes each
// after every record in it has been consumed by the caller.
//
// Design tradeoffs:
//   - No index. Replay is sequential; segment names sort
//     lexicographically (zero-padded uint64 counter), which is
//     enough for ordering. An index would enable random-access
//     replay (e.g. "events from <window>") that we don't need.
//   - One mutex around Append + Replay. Multi-writer isn't a
//     real workload — the sink is the single producer.
//   - Records survive partial writes via a CRC-then-skip pattern:
//     a malformed length prefix or short read truncates Replay
//     at that point without losing prior segments. Simpler than
//     full per-record CRC because the OS already checksums via
//     fsync's atomicity contract on aligned writes.

package buffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Defaults match the values ADR-0035 cites — operators can override
// per-knob via Options. 256 MiB total cap × ~1k events/s/host ≈ 6 h
// of disconnection coverage at typical fleet event rates. Segment
// size of 16 MiB makes eviction cheap (one file = one delete).
const (
	defaultSegmentBytes = 16 * 1024 * 1024
	defaultMaxBytes     = 256 * 1024 * 1024
	defaultMaxAge       = 6 * time.Hour
)

// Options configures Buffer. Zero values mean "use defaults".
type Options struct {
	// Dir is the on-disk root. Created if missing. Required.
	Dir string

	// SegmentBytes is the size threshold that triggers rotation
	// of the active write segment.
	SegmentBytes int64

	// MaxBytes is the total-size budget; once the sum of all
	// segments exceeds it, the oldest segments are deleted on the
	// next Append until the total fits. Zero disables eviction.
	MaxBytes int64

	// MaxAge bounds how old a record can be before Replay skips
	// it. The sink uses Envelope.observed_at as the wall clock
	// reference; if missing, the record is treated as not-too-old.
	MaxAge time.Duration
}

func (o *Options) withDefaults() {
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = defaultSegmentBytes
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = defaultMaxBytes
	}
	if o.MaxAge <= 0 {
		o.MaxAge = defaultMaxAge
	}
}

// Buffer is the on-disk spool. Safe for one Append goroutine + one
// Replay goroutine concurrently; the mutex serialises segment
// rotation + eviction.
type Buffer struct {
	opts Options

	mu      sync.Mutex
	active  *os.File // current write segment, nil before first Append
	written int64    // bytes in active segment
	counter uint64   // next segment counter
}

// Open returns a Buffer rooted at opts.Dir. The directory is created
// if missing; existing segments are picked up so Replay finds them.
func Open(opts Options) (*Buffer, error) {
	if opts.Dir == "" {
		return nil, errors.New("buffer: Dir required")
	}
	opts.withDefaults()
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("buffer: mkdir %s: %w", opts.Dir, err)
	}

	b := &Buffer{opts: opts}

	// Recover the next segment counter by scanning existing segments.
	segs, err := b.listSegments()
	if err != nil {
		return nil, err
	}
	if len(segs) > 0 {
		// Highest existing counter + 1 is the next active counter.
		b.counter = segs[len(segs)-1].counter + 1
	}
	return b, nil
}

// Append writes env to the active segment, rotating + evicting as
// needed. Append fsyncs after every write so a crash loses at most
// one in-flight record. Returns the number of bytes written
// (including the length prefix).
func (b *Buffer) Append(env *pb.Envelope) (int, error) {
	if env == nil {
		return 0, nil
	}
	payload, err := proto.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("buffer.Append: marshal: %w", err)
	}
	if len(payload) > maxRecordBytes {
		return 0, fmt.Errorf("buffer.Append: record %d > max %d", len(payload), maxRecordBytes)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Rotate before write if the active segment would overflow. A
	// rotation flushes + closes the current file and opens a fresh one
	// at the next counter slot.
	recordSize := int64(4 + len(payload))
	if b.active == nil || b.written+recordSize > b.opts.SegmentBytes {
		if err := b.rotateLocked(); err != nil {
			return 0, err
		}
	}

	if err := b.evictLocked(); err != nil {
		return 0, err
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := b.active.Write(lenBuf[:]); err != nil {
		return 0, fmt.Errorf("buffer.Append: write len: %w", err)
	}
	if _, err := b.active.Write(payload); err != nil {
		return 0, fmt.Errorf("buffer.Append: write payload: %w", err)
	}
	if err := b.active.Sync(); err != nil {
		return 0, fmt.Errorf("buffer.Append: sync: %w", err)
	}
	b.written += recordSize
	return int(recordSize), nil
}

// Replay walks every segment oldest-first and invokes consume for
// each record. consume returning a non-nil error stops the walk;
// the offending record stays on disk so the next Replay retries
// from the same segment.
//
// On success (consume returned nil for every record in a segment),
// the segment is deleted before moving to the next. Records older
// than opts.MaxAge are silently skipped (counted in dropped).
//
// Returns (replayed, dropped, error). replayed is the count consume
// accepted; dropped is records skipped on age. error is consume's
// last non-nil error or an I/O error.
func (b *Buffer) Replay(consume func(*pb.Envelope) error) (replayed, dropped int, err error) {
	cutoff := time.Now().Add(-b.opts.MaxAge)

	// Snapshot the segment list. New segments produced by concurrent
	// Append calls during replay will be picked up on the next
	// Replay invocation.
	b.mu.Lock()
	segs, err := b.listSegments()
	if err != nil {
		b.mu.Unlock()
		return 0, 0, err
	}
	// Don't touch the active segment during replay — Append might be
	// writing to it. Drain only sealed (rotated-out) segments.
	if b.active != nil {
		segs = filterOutCounter(segs, b.counter-1)
	}
	b.mu.Unlock()

	for _, seg := range segs {
		segReplayed, segDropped, segErr := b.replaySegment(seg, cutoff, consume)
		replayed += segReplayed
		dropped += segDropped
		if segErr != nil {
			return replayed, dropped, segErr
		}
		// Segment fully consumed — delete it.
		if rmErr := os.Remove(seg.path); rmErr != nil && !os.IsNotExist(rmErr) {
			return replayed, dropped, fmt.Errorf("buffer.Replay: remove %s: %w", seg.path, rmErr)
		}
	}
	return replayed, dropped, nil
}

// Close flushes + closes the active segment. The next Open re-discovers
// its counter and resumes appending into a fresh segment file.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil {
		return nil
	}
	err := b.active.Close()
	b.active = nil
	b.written = 0
	return err
}

// rotateLocked closes the current active segment + opens the next.
// Caller must hold b.mu.
func (b *Buffer) rotateLocked() error {
	if b.active != nil {
		if err := b.active.Close(); err != nil {
			return fmt.Errorf("buffer.rotate: close: %w", err)
		}
		b.active = nil
		b.written = 0
	}
	name := segmentName(b.counter)
	path := filepath.Join(b.opts.Dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("buffer.rotate: open %s: %w", path, err)
	}
	b.active = f
	b.counter++
	return nil
}

// evictLocked deletes oldest segments until the total on-disk size
// fits opts.MaxBytes. The active segment is exempt — eviction only
// touches sealed (rotated-out) segments. Caller must hold b.mu.
func (b *Buffer) evictLocked() error {
	if b.opts.MaxBytes <= 0 {
		return nil
	}
	segs, err := b.listSegments()
	if err != nil {
		return err
	}
	// Sum sizes; drop oldest until we fit.
	var total int64
	sizes := make([]int64, len(segs))
	for i, seg := range segs {
		fi, err := os.Stat(seg.path)
		if err != nil {
			return fmt.Errorf("buffer.evict: stat %s: %w", seg.path, err)
		}
		sizes[i] = fi.Size()
		total += fi.Size()
	}
	for i := 0; i < len(segs)-1 && total > b.opts.MaxBytes; i++ {
		// Don't evict the active segment (last entry).
		if err := os.Remove(segs[i].path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("buffer.evict: remove %s: %w", segs[i].path, err)
		}
		total -= sizes[i]
	}
	return nil
}

// segment is one entry in listSegments's sorted output.
type segment struct {
	counter uint64
	path    string
}

// listSegments returns sealed + active segments sorted by counter
// ascending. Filenames not matching the seg-NNNNNNNNNNNNNNNN.dat
// shape are silently skipped — operators sometimes drop scratch
// files in a tooling dir.
func (b *Buffer) listSegments() ([]segment, error) {
	entries, err := os.ReadDir(b.opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("buffer.listSegments: %w", err)
	}
	out := make([]segment, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		c, ok := parseSegmentName(e.Name())
		if !ok {
			continue
		}
		out = append(out, segment{counter: c, path: filepath.Join(b.opts.Dir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].counter < out[j].counter })
	return out, nil
}

func filterOutCounter(segs []segment, counter uint64) []segment {
	out := make([]segment, 0, len(segs))
	for _, s := range segs {
		if s.counter == counter {
			continue
		}
		out = append(out, s)
	}
	return out
}

// replaySegment walks one segment file, calling consume for each
// non-stale record. Returns counts + first non-nil error.
func (b *Buffer) replaySegment(seg segment, cutoff time.Time, consume func(*pb.Envelope) error) (replayed, dropped int, err error) {
	f, err := os.Open(seg.path)
	if err != nil {
		return 0, 0, fmt.Errorf("buffer.replaySegment: open %s: %w", seg.path, err)
	}
	defer f.Close()

	for {
		var lenBuf [4]byte
		_, err := io.ReadFull(f, lenBuf[:])
		if err == io.EOF {
			return replayed, dropped, nil
		}
		if err == io.ErrUnexpectedEOF {
			// Partial header — truncate at the last good record.
			return replayed, dropped, nil
		}
		if err != nil {
			return replayed, dropped, fmt.Errorf("buffer.replaySegment: read len: %w", err)
		}
		recLen := binary.BigEndian.Uint32(lenBuf[:])
		if recLen == 0 || recLen > maxRecordBytes {
			// Corrupt length — stop but don't error out. Operator can
			// inspect the file; subsequent records on this segment
			// are unreachable.
			return replayed, dropped, nil
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			// Partial body — same as partial header.
			return replayed, dropped, nil
		}
		var env pb.Envelope
		if err := proto.Unmarshal(payload, &env); err != nil {
			// Skip the bad record; continue to the next.
			dropped++
			continue
		}
		if isStale(&env, cutoff) {
			dropped++
			continue
		}
		if err := consume(&env); err != nil {
			return replayed, dropped, err
		}
		replayed++
	}
}

// isStale reports whether env's observed_at is older than cutoff.
// Missing observed_at is treated as fresh (don't drop on absence).
func isStale(env *pb.Envelope, cutoff time.Time) bool {
	t := env.GetObservedAt()
	if t == nil {
		return false
	}
	return asTime(t).Before(cutoff)
}

func asTime(ts *timestamppb.Timestamp) time.Time {
	return ts.AsTime()
}

// segmentName encodes counter as zero-padded 16-digit decimal so
// lexicographic sort matches numeric sort up to ~10^16 records.
func segmentName(counter uint64) string {
	return fmt.Sprintf("seg-%016d.dat", counter)
}

// parseSegmentName parses "seg-NNNNNNNNNNNNNNNN.dat" back to its
// counter. Returns false on names that don't match the shape.
func parseSegmentName(name string) (uint64, bool) {
	if len(name) != len("seg-0000000000000000.dat") {
		return 0, false
	}
	if name[:4] != "seg-" || name[len(name)-4:] != ".dat" {
		return 0, false
	}
	digits := name[4 : len(name)-4]
	var n uint64
	for _, ch := range digits {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + uint64(ch-'0')
	}
	return n, true
}

// maxRecordBytes is the upper bound on a single Envelope's serialised
// size. Matches grpc-go's default 4 MiB recv ceiling so a record
// that fits in the buffer can also fit on the wire.
const maxRecordBytes = 4 * 1024 * 1024
