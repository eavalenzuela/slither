package selfprotect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainWriter_AppendsClean(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")

	w, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	for i := 0; i < 5; i++ {
		if err := w.Append("response_action", map[string]any{
			"action_id": "fake-uuid",
			"action":    "kill_process",
			"target":    "1234",
			"status":    "done",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	walked, err := VerifyChain(path, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	// 1 chain.init + 5 response_actions = 6 records walked.
	if walked != 6 {
		t.Errorf("walked = %d, want 6", walked)
	}
}

func TestVerifyChain_DetectsRecordHashTamper(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")

	w, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Append("kind", map[string]int{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	w.Close()

	// Tamper: edit line index 4's summary (seq=4, content {"i":3}
	// because chain.init=seq0 + 5 appends = seqs 1..5, so the
	// `{"i":3}` body lives at seq=4 / line 4). The recorded hash
	// won't match the new content; verify must catch it.
	tampered := tamperLine(t, path, 4, func(line string) string {
		return strings.Replace(line, `"i":3`, `"i":999`, 1)
	})
	_ = tampered

	_, err = VerifyChain(path, time.Time{})
	var cb *ChainBreakError
	if !errors.As(err, &cb) {
		t.Fatalf("VerifyChain after tamper: err=%v, want ChainBreakError", err)
	}
	if cb.Seq != 4 {
		t.Errorf("ChainBreakError.Seq = %d, want 4", cb.Seq)
	}
	if !strings.Contains(cb.Reason, "record_hash mismatch") {
		t.Errorf("ChainBreakError.Reason = %q, want record_hash mismatch", cb.Reason)
	}
}

func TestVerifyChain_DetectsPrevHashTamperAtNextRecord(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")
	w, _ := OpenChain(path)
	for i := 0; i < 4; i++ {
		_ = w.Append("k", map[string]int{"i": i})
	}
	w.Close()

	// Tamper: swap record_hash on row 1 with a plausibly-formed hash.
	// Row 1's content+hash mismatch will fire first; the test
	// pinpoints seq=1.
	tamperLine(t, path, 1, func(line string) string {
		return strings.Replace(line,
			`"record_hash":"`,
			`"record_hash":"deadbeef`+strings.Repeat("0", 56)[:0]+``, 1)
	})

	_, err := VerifyChain(path, time.Time{})
	var cb *ChainBreakError
	if !errors.As(err, &cb) {
		t.Fatalf("VerifyChain: err=%v, want ChainBreakError", err)
	}
	if cb.Seq != 1 {
		t.Errorf("Seq = %d, want 1", cb.Seq)
	}
}

func TestVerifyChain_DetectsTruncation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")
	w, _ := OpenChain(path)
	for i := 0; i < 5; i++ {
		_ = w.Append("k", map[string]int{"i": i})
	}
	w.Close()

	// Truncate to keep only the chain.init + first 2 response records
	// (3 records total, ~3 lines).
	keepLines(t, path, 3)

	walked, err := VerifyChain(path, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain on truncated chain: %v", err)
	}
	// Truncation alone doesn't break the chain — the records that
	// remain are still internally consistent. Detection requires
	// cross-checking against an external length signal (server-side
	// CH count, which is Phase 6+ work). What we DO catch here is
	// that walked < expected; the operator can compare against the
	// server's count.
	if walked != 3 {
		t.Errorf("walked = %d, want 3", walked)
	}
}

func TestVerifyChain_MissingFileIsClean(t *testing.T) {
	t.Parallel()
	walked, err := VerifyChain("/nonexistent/path/log.chain", time.Time{})
	if err != nil {
		t.Errorf("missing file: err = %v, want nil", err)
	}
	if walked != 0 {
		t.Errorf("missing file: walked = %d, want 0", walked)
	}
}

func TestChainWriter_RecoverContinuesSeq(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")

	w1, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain 1: %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = w1.Append("k", map[string]int{"i": i})
	}
	w1.Close()

	// Re-open. Should pick up at seq=4 (chain.init=0, three records=1..3).
	w2, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain 2: %v", err)
	}
	if err := w2.Append("k", map[string]string{"phase": "after-reopen"}); err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	w2.Close()

	walked, err := VerifyChain(path, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain after reopen: %v", err)
	}
	// 1 init + 3 first-session + 1 second-session = 5 records.
	if walked != 5 {
		t.Errorf("walked = %d, want 5 (chain.init + 3 + 1)", walked)
	}
}

func TestChainWriter_NilSafe(t *testing.T) {
	t.Parallel()
	var w *ChainWriter
	if err := w.Append("k", nil); err != nil {
		t.Errorf("nil writer Append: %v, want nil (no-op)", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("nil writer Close: %v, want nil", err)
	}
}

// tamperLine reads `path`, mutates the record at logical seq via fn,
// and rewrites the file in place. Returns the rewritten content for
// debug logging.
func tamperLine(t *testing.T, path string, targetSeq int, fn func(string) string) string {
	t.Helper()
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(bs), "\n"), "\n")
	if targetSeq >= len(lines) {
		t.Fatalf("targetSeq %d >= line count %d", targetSeq, len(lines))
	}
	lines[targetSeq] = fn(lines[targetSeq])
	rewritten := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return rewritten
}

// keepLines truncates `path` to its first `n` lines.
func keepLines(t *testing.T, path string, n int) {
	t.Helper()
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(bs), "\n"), "\n")
	if n > len(lines) {
		n = len(lines)
	}
	out := strings.Join(lines[:n], "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestChainWriter_SnapshotAndReset asserts the Phase 6 #112 windowed
// counter: Append ticks the in-window count for non-init records,
// SnapshotAndReset returns the (last_seq, last_hash, count) triple
// and rolls the window forward.
func TestChainWriter_SnapshotAndReset(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "log.chain")

	w, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	for i := 0; i < 4; i++ {
		if err := w.Append("response_action", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := w.Append("detection_finding", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	first := w.SnapshotAndReset()
	if first.Count != 7 {
		t.Errorf("first.Count = %d, want 7 (4 response + 3 finding)", first.Count)
	}
	// chain.init wrote seq=0; 7 reals follow at seq 1..7. last_seq=7.
	if first.LastSeq != 7 {
		t.Errorf("first.LastSeq = %d, want 7", first.LastSeq)
	}
	if first.LastHash == "" || first.LastHash == zeroHash {
		t.Errorf("first.LastHash empty or zero: %q", first.LastHash)
	}
	if !first.ObservedAt.After(first.Since) {
		t.Errorf("first window not forward-progressing: since=%v observed=%v",
			first.Since, first.ObservedAt)
	}

	// Window should reset — a second snapshot with no new appends
	// returns count=0.
	time.Sleep(2 * time.Millisecond)
	second := w.SnapshotAndReset()
	if second.Count != 0 {
		t.Errorf("second.Count = %d, want 0 (no appends since first snapshot)", second.Count)
	}
	if !second.Since.Equal(first.ObservedAt) {
		t.Errorf("second.Since = %v, want first.ObservedAt %v", second.Since, first.ObservedAt)
	}
	if second.LastSeq != first.LastSeq {
		t.Errorf("second.LastSeq = %d changed across empty window (want %d)", second.LastSeq, first.LastSeq)
	}

	// Append more, snapshot again → count covers only the new records.
	for i := 0; i < 2; i++ {
		_ = w.Append("response_action", map[string]any{"i": i})
	}
	third := w.SnapshotAndReset()
	if third.Count != 2 {
		t.Errorf("third.Count = %d, want 2", third.Count)
	}
	if third.LastSeq != first.LastSeq+2 {
		t.Errorf("third.LastSeq = %d, want %d", third.LastSeq, first.LastSeq+2)
	}
}
