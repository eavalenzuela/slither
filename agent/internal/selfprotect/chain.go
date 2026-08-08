// Phase 5 #95 — tamper-evident hash-chain log.
//
// Each response_action terminal transition + each emitted detection
// finding writes one line to /var/lib/slither/log.chain. Records are
// linked: every record's prev_hash equals the previous record's
// record_hash. Truncating, reordering, or editing any record breaks
// the chain at the first mutated row.
//
// Threat model: a local-root attacker who can write to log.chain.
// We don't pretend to defend against an attacker who can write the
// chain AND control the agent's signing key — that's a Phase 6+
// problem covered by remote attestation. What we do guarantee:
//
//   - Truncation is detected (chain length < expected; #102 docs
//     the expected-length signal: server-side cross-check against
//     CH-stored detection findings).
//   - Single-record edits break record_hash on that record.
//   - Reorder breaks prev_hash linkage.
//   - Insertion breaks prev_hash on the next record.
//   - Replay-then-extend by the attacker writes valid records but
//     under their own hash chain — server-side cross-check still
//     catches missing records (#102).
//   - Edit-then-relink (rewrite record n, recompute its record_hash,
//     re-link n+1..N so the file self-verifies) is caught by the
//     server, not by us. Phase 7 / ADR-0042 ships every record's
//     (seq, kind, prev_hash, record_hash) tuple to the server, which
//     keeps them as an append-only witness. Relinking necessarily
//     changes the tail's record_hash, and the tail is exactly what
//     the next summary's continuity check anchors on — so the edit
//     surfaces within one summary interval.
//
// What we don't try to do:
//   - Encrypt the chain. The point is auditability — operators need
//     to read the JSON without keys.
//   - Sign each record with a key. Keys live on the agent host;
//     a local-root attacker who can write the chain can also read
//     the key.

package selfprotect

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ChainRecord is one row in log.chain. Marshalled as JSON; the
// canonical hash input is built from the same fields in a fixed,
// pipe-delimited order so the hash doesn't depend on JSON's whitespace
// or field-order quirks.
type ChainRecord struct {
	Seq        uint64          `json:"seq"`
	TS         string          `json:"ts"`
	Kind       string          `json:"kind"`
	Summary    json.RawMessage `json:"summary"`
	PrevHash   string          `json:"prev_hash"`
	RecordHash string          `json:"record_hash"`
}

// ChainWriter appends records under a process-wide mutex. Only one
// ChainWriter should exist per chain file — multiple writers would
// race on the seq counter + prev_hash bookkeeping. The agent's app.Run
// constructs one + threads it into respond.Executor and ruleengine.
type ChainWriter struct {
	path string

	mu       sync.Mutex
	file     *os.File
	seq      uint64
	prevHash string // hex sha256 of last record (or zeros if empty)

	// Phase 6 #112 windowed counter — number of summary-eligible
	// records appended since the last Snapshot() call (or since
	// OpenChain when no snapshot has been taken yet). Reset by
	// SnapshotAndReset so consecutive summaries cover disjoint
	// windows.
	windowCount uint64
	windowSince time.Time

	// Phase 7 / ADR-0042 link witness buffer. Holds one ChainLink per
	// record appended in the window, ascending by seq, so the summary
	// can ship them to the server. Unlike windowCount this INCLUDES
	// chain.init — it is a real chain record and the server needs it
	// to anchor seq=0's prev_hash against the zero sentinel.
	//
	// Bounded at maxWindowLinks. On overflow the OLDEST links are
	// dropped and windowTruncated is set: the tail is what the server
	// anchors its next continuity check on, so the tail is the part
	// that must never be lost.
	windowLinks     []ChainLink
	windowTruncated bool
}

// ChainLink is one record's chain identity with its content stripped.
// Phase 7 / ADR-0042 — this is what the agent ships to the server so
// the server can replay linkage without ever seeing (or being able to
// recompute) the hashed record body.
type ChainLink struct {
	Seq        uint64
	Kind       string
	PrevHash   string
	RecordHash string
}

// maxWindowLinks bounds the in-memory link buffer. 512 links is ~75 KiB
// and covers well past the 5-minute summary interval on any sane host —
// a burst that overruns it (mass-rename ransomware firing hundreds of
// findings) ships the most recent 512 with links_truncated set rather
// than growing without bound.
const maxWindowLinks = 512

// zeroHash is the sentinel prev_hash for the first record in a chain.
const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// OpenChain opens (or creates) the chain file at path. If the file
// already exists, the writer scans it once to recover the next seq
// and prev_hash. Tampered chains still open — the writer doesn't
// validate on open; that's verify-logs's job. Bringing up the agent
// after someone monkeyed with log.chain shouldn't refuse to start
// new audit work.
func OpenChain(path string) (*ChainWriter, error) {
	w := &ChainWriter{
		path:        path,
		prevHash:    zeroHash,
		windowSince: time.Now().UTC(),
	}

	// Recover state if the file exists. Best-effort: a malformed last
	// line (write was interrupted, or operator hand-edited) gets
	// silently truncated to the last well-formed record.
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		if err := w.recover(); err != nil {
			return nil, fmt.Errorf("selfprotect.OpenChain: recover %s: %w", path, err)
		}
	}

	// Open append-only. 0600 — the chain is the agent's tamper-
	// evidence bookkeeping, not a syslog channel for everyone.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: path is the configured chain location, not request-derived. See SECURITY.md "Risk dispositioning".
	if err != nil {
		return nil, fmt.Errorf("selfprotect.OpenChain: %w", err)
	}
	w.file = f

	// First-ever record: a self-describing chain.init line so verify-logs
	// has a synthetic seq=0 anchor. Subsequent records start at seq=1.
	if w.seq == 0 {
		init, _ := json.Marshal(map[string]string{
			"agent_pid":   fmt.Sprintf("%d", os.Getpid()),
			"chain_start": time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err := w.append("chain.init", init); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("selfprotect.OpenChain: init record: %w", err)
		}
	}

	return w, nil
}

// Append writes a new record with the given kind + summary. summary
// is marshalled as the record's `summary` field; nil emits an empty
// object. Returns nil on success; errors mean the write hit fsync or
// disk-full, in which case the caller's context will surface it.
func (w *ChainWriter) Append(kind string, summary any) error {
	if w == nil || w.file == nil {
		return nil // no-op when chain is disabled
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	var summaryJSON json.RawMessage
	if summary == nil {
		summaryJSON = json.RawMessage("{}")
	} else {
		buf, err := json.Marshal(summary)
		if err != nil {
			return fmt.Errorf("selfprotect.ChainWriter.Append: marshal summary: %w", err)
		}
		summaryJSON = buf
	}
	return w.append(kind, summaryJSON)
}

// append writes one record. Caller must hold w.mu.
func (w *ChainWriter) append(kind string, summary json.RawMessage) error {
	rec := ChainRecord{
		Seq:      w.seq,
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Kind:     kind,
		Summary:  summary,
		PrevHash: w.prevHash,
	}
	rec.RecordHash = hashRecord(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("selfprotect.ChainWriter.append: marshal: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("selfprotect.ChainWriter.append: write: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("selfprotect.ChainWriter.append: sync: %w", err)
	}

	w.prevHash = rec.RecordHash
	w.seq++
	// Phase 6 #112: count summary-eligible records (everything except
	// the synthetic chain.init anchor; the server has no equivalent
	// row for that). Counted here under the same mutex Append holds
	// so Snapshot() reads a consistent (last_seq, last_hash, count)
	// triple.
	if kind != "chain.init" {
		w.windowCount++
	}
	// ADR-0042: every record contributes a link, chain.init included.
	w.pushLink(ChainLink{
		Seq:        rec.Seq,
		Kind:       rec.Kind,
		PrevHash:   rec.PrevHash,
		RecordHash: rec.RecordHash,
	})
	return nil
}

// pushLink appends one link to the window buffer, dropping from the
// front (and flagging truncation) once the buffer is full. Caller must
// hold w.mu.
func (w *ChainWriter) pushLink(l ChainLink) {
	w.windowLinks = append(w.windowLinks, l)
	w.capWindowLinks()
}

// capWindowLinks trims the buffer to its most recent maxWindowLinks
// entries, setting windowTruncated if anything was dropped. Caller must
// hold w.mu.
func (w *ChainWriter) capWindowLinks() {
	if len(w.windowLinks) <= maxWindowLinks {
		return
	}
	drop := len(w.windowLinks) - maxWindowLinks
	n := copy(w.windowLinks, w.windowLinks[drop:])
	w.windowLinks = w.windowLinks[:n]
	w.windowTruncated = true
}

// ChainSummarySnapshot is the Phase 6 #112 view of the chain writer's
// state — last_seq, last_hash (hex sha256 of the most recent record),
// the window's record count, and the [since, observed_at) bounds the
// count covers. observed_at is set by SnapshotAndReset to the moment
// the snapshot was taken.
type ChainSummarySnapshot struct {
	LastSeq    uint64
	LastHash   string
	Count      uint64
	Since      time.Time
	ObservedAt time.Time

	// Links + LinksTruncated are the Phase 7 / ADR-0042 witness
	// payload. Links is ascending by seq and includes chain.init.
	Links          []ChainLink
	LinksTruncated bool
}

// SnapshotAndReset returns the current chain summary and rolls the
// internal window forward — the next call covers a fresh disjoint
// window starting at this snapshot's observed_at. Phase 6 #112.
//
// Safe to call concurrently with Append; both share w.mu.
func (w *ChainWriter) SnapshotAndReset() ChainSummarySnapshot {
	if w == nil {
		return ChainSummarySnapshot{}
	}
	now := time.Now().UTC()
	w.mu.Lock()
	defer w.mu.Unlock()
	// last_seq is the seq of the most recent appended record. seq
	// itself is the NEXT seq to use, so the most recent is seq-1
	// (when seq>0) or 0 when nothing has been appended (shouldn't
	// happen — OpenChain always writes chain.init).
	var lastSeq uint64
	if w.seq > 0 {
		lastSeq = w.seq - 1
	}
	snap := ChainSummarySnapshot{
		LastSeq:        lastSeq,
		LastHash:       w.prevHash,
		Count:          w.windowCount,
		Since:          w.windowSince,
		ObservedAt:     now,
		Links:          w.windowLinks,
		LinksTruncated: w.windowTruncated,
	}
	w.windowCount = 0
	w.windowSince = now
	// Hand the backing array to the snapshot rather than reusing it —
	// the caller marshals it onto the wire after we've released the
	// mutex, so a shared array would race with the next Append.
	w.windowLinks = nil
	w.windowTruncated = false
	return snap
}

// ReturnWindow folds an unshipped snapshot back into the live window.
// The summary sink is a capacity-4 channel that drops rather than
// blocks (a wedged sink must not stall the agent), and without this a
// dropped summary would silently discard that window's links — leaving
// the server's witness with a permanent hole that every later segment
// would report as a sequence gap.
//
// Merging is order-preserving: the returned links precede whatever has
// been appended since, and the combined buffer is re-capped, so a
// return that overflows degrades to the same truncated-at-the-head
// state a burst would have produced anyway.
func (w *ChainWriter) ReturnWindow(snap ChainSummarySnapshot) {
	if w == nil || (len(snap.Links) == 0 && snap.Count == 0) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.windowCount += snap.Count
	if !snap.Since.IsZero() && snap.Since.Before(w.windowSince) {
		w.windowSince = snap.Since
	}
	if snap.LinksTruncated {
		w.windowTruncated = true
	}
	if len(snap.Links) > 0 {
		merged := make([]ChainLink, 0, len(snap.Links)+len(w.windowLinks))
		merged = append(merged, snap.Links...)
		merged = append(merged, w.windowLinks...)
		w.windowLinks = merged
		w.capWindowLinks()
	}
}

// Close flushes + releases the chain file. Called by the agent on
// graceful shutdown so the last record's fsync lands before exit.
func (w *ChainWriter) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.file.Close()
	w.file = nil
	return err
}

// recover scans the existing chain to set w.seq + w.prevHash. Stops
// at the last well-formed record; any trailing garbage (interrupted
// write, malformed line) is left in place for verify-logs to flag.
func (w *ChainWriter) recover() error {
	f, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow large summaries (collect_artifacts manifest bundles run
	// kilobytes). Default scanner limit is 64 KiB; bump to 1 MiB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		var rec ChainRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			// Stop at first malformed line. The next Append continues
			// from the last good record's seq + hash, leaving the
			// trailing garbage in place. Verify-logs will surface it
			// as a chain break.
			break
		}
		w.seq = rec.Seq + 1
		w.prevHash = rec.RecordHash
		// ADR-0042: re-seed the link window from disk so the first
		// summary after a restart overlaps the last one shipped before
		// it. Without this, every restart would punch a gap into the
		// server's witness — the links appended between the last tick
		// and the shutdown live only in memory. The overlap is not
		// wasted work: re-reported links are checked for equality
		// against what the server already stored, which is a second
		// independent way to catch an edit-then-relink.
		w.pushLink(ChainLink{
			Seq:        rec.Seq,
			Kind:       rec.Kind,
			PrevHash:   rec.PrevHash,
			RecordHash: rec.RecordHash,
		})
	}
	// A backfill that hit the cap is not a truncated *window* — the
	// window simply starts further back than the whole chain. Reporting
	// it as truncation would make every restart of a long-lived agent
	// look like a dropped burst.
	w.windowTruncated = false
	return sc.Err()
}

// hashRecord computes the canonical hash input + returns its hex
// sha256. The format is fixed: pipe-separated, no whitespace, fields
// in declaration order. Stable across JSON re-serialisation quirks.
func hashRecord(r ChainRecord) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s",
		r.Seq, r.TS, r.Kind, string(r.Summary), r.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// ChainBreakError is returned by VerifyChain when a chain inconsistency
// is found. Seq points at the offending record (or the position where
// a record was expected); Reason describes what broke.
type ChainBreakError struct {
	Seq    uint64
	Reason string
}

func (e *ChainBreakError) Error() string {
	return fmt.Sprintf("chain break at seq=%d: %s", e.Seq, e.Reason)
}

// VerifyChain walks path and returns the number of records walked +
// nil on success, or a *ChainBreakError pinpointing the first
// inconsistency. If since is non-zero, records older than since are
// skipped — useful for "verify the last 24h" rather than walking a
// year of audit history.
//
// Verification rules:
//   - Each record's record_hash must equal hashRecord(record).
//   - Each record's prev_hash must equal the previous record's
//     record_hash (zeroHash for seq=0).
//   - Sequence numbers must increment by 1 starting from the first
//     record.
//   - Records must parse as JSON.
//
// A missing file is not an error — `walked=0, nil`. A fresh agent
// that never fired a response or detection has no chain to verify.
func VerifyChain(path string, since time.Time) (uint64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the configured chain location, not request-derived. See SECURITY.md "Risk dispositioning".
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("selfprotect.VerifyChain: %w", err)
	}
	defer f.Close()

	return verifyReader(f, since)
}

func verifyReader(r io.Reader, since time.Time) (uint64, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		walked    uint64
		expectSeq uint64
		prevHash  = zeroHash
	)

	for sc.Scan() {
		var rec ChainRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return walked, &ChainBreakError{
				Seq:    expectSeq,
				Reason: fmt.Sprintf("malformed JSON: %v", err),
			}
		}
		if rec.Seq != expectSeq {
			return walked, &ChainBreakError{
				Seq:    rec.Seq,
				Reason: fmt.Sprintf("expected seq=%d, got %d", expectSeq, rec.Seq),
			}
		}
		if rec.PrevHash != prevHash {
			return walked, &ChainBreakError{
				Seq: rec.Seq,
				Reason: fmt.Sprintf("prev_hash mismatch: expected %s, got %s",
					prevHash, rec.PrevHash),
			}
		}
		want := hashRecord(rec)
		if rec.RecordHash != want {
			return walked, &ChainBreakError{
				Seq: rec.Seq,
				Reason: fmt.Sprintf("record_hash mismatch: expected %s, got %s",
					want, rec.RecordHash),
			}
		}

		// Apply since-filter to the WALKED counter, not to the chain
		// validation itself — every record gets hash-verified
		// regardless of since (skipping verification under since
		// would let an attacker hide tampering by predating records).
		if !since.IsZero() {
			if ts, err := time.Parse(time.RFC3339Nano, rec.TS); err == nil && ts.Before(since) {
				expectSeq++
				prevHash = rec.RecordHash
				continue
			}
		}

		walked++
		expectSeq++
		prevHash = rec.RecordHash
	}
	if err := sc.Err(); err != nil {
		return walked, fmt.Errorf("selfprotect.VerifyChain: scan: %w", err)
	}
	return walked, nil
}
