package selfprotect

import (
	"path/filepath"
	"testing"
	"time"
)

// assertChained checks that a link slice is contiguous and that each
// link's prev_hash is the previous link's record_hash — the exact
// property the server replays.
func assertChained(t *testing.T, links []ChainLink) {
	t.Helper()
	for i, l := range links {
		if l.RecordHash == "" || l.PrevHash == "" {
			t.Fatalf("link %d has an empty hash: %+v", i, l)
		}
		if i == 0 {
			continue
		}
		if l.Seq != links[i-1].Seq+1 {
			t.Fatalf("links not contiguous at index %d: seq %d follows %d",
				i, l.Seq, links[i-1].Seq)
		}
		if l.PrevHash != links[i-1].RecordHash {
			t.Fatalf("linkage break at seq %d: prev_hash %s != preceding record_hash %s",
				l.Seq, l.PrevHash, links[i-1].RecordHash)
		}
	}
}

// The window buffer must carry every record including chain.init —
// the server needs seq=0 to anchor on the zero sentinel.
func TestSnapshot_LinksIncludeChainInit(t *testing.T) {
	t.Parallel()
	w, err := OpenChain(filepath.Join(t.TempDir(), "log.chain"))
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		if err := w.Append("detection_finding", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	snap := w.SnapshotAndReset()
	if len(snap.Links) != 4 {
		t.Fatalf("len(Links) = %d, want 4 (chain.init + 3)", len(snap.Links))
	}
	if snap.Links[0].Seq != 0 || snap.Links[0].Kind != "chain.init" {
		t.Errorf("first link = %+v, want the seq=0 chain.init anchor", snap.Links[0])
	}
	if snap.Links[0].PrevHash != zeroHash {
		t.Errorf("chain.init prev_hash = %q, want the zero sentinel", snap.Links[0].PrevHash)
	}
	// Count stays at 3 — chain.init has no server-side counterpart, so
	// including it would break the count cross-check it predates.
	if snap.Count != 3 {
		t.Errorf("Count = %d, want 3 (chain.init excluded from the count)", snap.Count)
	}
	assertChained(t, snap.Links)
	if snap.LinksTruncated {
		t.Error("LinksTruncated set on a 4-record window")
	}
	if snap.Links[len(snap.Links)-1].RecordHash != snap.LastHash {
		t.Error("last link's record_hash disagrees with LastHash")
	}
}

// A snapshot hands the buffer over: the next window starts empty so
// consecutive segments don't double-report.
func TestSnapshot_ResetsLinkWindow(t *testing.T) {
	t.Parallel()
	w, err := OpenChain(filepath.Join(t.TempDir(), "log.chain"))
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	_ = w.Append("response_action", nil)
	first := w.SnapshotAndReset()
	if len(first.Links) != 2 {
		t.Fatalf("first window links = %d, want 2", len(first.Links))
	}

	second := w.SnapshotAndReset()
	if len(second.Links) != 0 {
		t.Errorf("second window links = %d, want 0", len(second.Links))
	}

	_ = w.Append("response_action", nil)
	third := w.SnapshotAndReset()
	if len(third.Links) != 1 {
		t.Fatalf("third window links = %d, want 1", len(third.Links))
	}
	// Continuity across the window boundary is what the server anchors
	// on, so it has to hold even though the buffer was cleared.
	if third.Links[0].PrevHash != first.Links[len(first.Links)-1].RecordHash {
		t.Error("third window does not chain onto the first window's tail")
	}
}

// Overflow keeps the TAIL, because that is what the server's next
// continuity check anchors on. Losing the tail would break the witness
// permanently; losing the head costs one window.
func TestSnapshot_OverflowKeepsTailAndFlagsTruncation(t *testing.T) {
	t.Parallel()
	w, err := OpenChain(filepath.Join(t.TempDir(), "log.chain"))
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	const extra = 20
	for i := 0; i < maxWindowLinks+extra; i++ {
		if err := w.Append("detection_finding", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	snap := w.SnapshotAndReset()
	if !snap.LinksTruncated {
		t.Error("LinksTruncated not set after overflowing the buffer")
	}
	if len(snap.Links) != maxWindowLinks {
		t.Fatalf("len(Links) = %d, want %d", len(snap.Links), maxWindowLinks)
	}
	if got := snap.Links[len(snap.Links)-1].Seq; got != snap.LastSeq {
		t.Errorf("tail link seq = %d, want LastSeq %d — the tail must survive", got, snap.LastSeq)
	}
	if snap.Links[0].Seq == 0 {
		t.Error("head was kept; overflow must drop from the front")
	}
	assertChained(t, snap.Links)
}

// A restart re-seeds the window from disk so the server's witness
// doesn't get a hole for whatever was appended after the last tick.
func TestOpenChain_RecoverBackfillsLinkWindow(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "log.chain")

	w1, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err = w1.Append("response_action", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	before := w1.SnapshotAndReset()
	// Two more records land after the tick, then the agent dies.
	_ = w1.Append("detection_finding", nil)
	_ = w1.Append("detection_finding", nil)
	if err = w1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w2, err := OpenChain(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()

	snap := w2.SnapshotAndReset()
	if len(snap.Links) != 8 {
		t.Fatalf("backfilled links = %d, want 8 (whole chain re-seeded)", len(snap.Links))
	}
	assertChained(t, snap.Links)
	if snap.LinksTruncated {
		t.Error("a backfill under the cap must not report truncation")
	}
	// The unshipped tail is present — that is the hole this closes.
	if snap.Links[len(snap.Links)-1].Seq != 7 {
		t.Errorf("tail seq = %d, want 7", snap.Links[len(snap.Links)-1].Seq)
	}
	// And the overlap with what was already shipped is byte-identical,
	// which is what lets the server treat a re-report as a second
	// tamper check rather than a contradiction.
	for _, prior := range before.Links {
		found := false
		for _, l := range snap.Links {
			if l.Seq == prior.Seq {
				found = true
				if l.RecordHash != prior.RecordHash || l.PrevHash != prior.PrevHash {
					t.Errorf("seq %d changed across restart: %+v vs %+v", l.Seq, l, prior)
				}
			}
		}
		if !found {
			t.Errorf("seq %d missing from the backfilled window", prior.Seq)
		}
	}
	// Count covers only new appends — the backfill is witness data, not
	// new work, and counting it would break the count cross-check.
	if snap.Count != 0 {
		t.Errorf("Count = %d, want 0 (backfill must not inflate the count)", snap.Count)
	}
}

// A backfill larger than the cap is not a truncated window — the
// window simply starts further back than the whole chain. Reporting it
// as truncation would make every restart of a long-lived agent look
// like a dropped burst.
func TestOpenChain_LargeBackfillDoesNotFlagTruncation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "log.chain")

	w1, err := OpenChain(path)
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	for i := 0; i < maxWindowLinks+10; i++ {
		if err = w1.Append("detection_finding", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = w1.Close()

	w2, err := OpenChain(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()

	snap := w2.SnapshotAndReset()
	if snap.LinksTruncated {
		t.Error("large backfill reported as a truncated window")
	}
	if len(snap.Links) != maxWindowLinks {
		t.Errorf("len(Links) = %d, want the cap %d", len(snap.Links), maxWindowLinks)
	}
	assertChained(t, snap.Links)
}

// A dropped summary must not lose its links, or the server's witness
// gets a permanent hole that every later segment reports as a gap.
func TestReturnWindow_RestoresDroppedSnapshot(t *testing.T) {
	t.Parallel()
	w, err := OpenChain(filepath.Join(t.TempDir(), "log.chain"))
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		_ = w.Append("response_action", map[string]any{"i": i})
	}
	dropped := w.SnapshotAndReset()
	if dropped.Count != 3 || len(dropped.Links) != 4 {
		t.Fatalf("setup: count=%d links=%d", dropped.Count, len(dropped.Links))
	}

	// The tick after the drop appends one more record.
	_ = w.Append("detection_finding", nil)
	w.ReturnWindow(dropped)

	next := w.SnapshotAndReset()
	if next.Count != 4 {
		t.Errorf("Count = %d, want 4 (3 returned + 1 new)", next.Count)
	}
	if len(next.Links) != 5 {
		t.Fatalf("len(Links) = %d, want 5 (4 returned + 1 new)", len(next.Links))
	}
	if next.Links[0].Seq != 0 {
		t.Errorf("returned links not re-prepended in order: first seq = %d", next.Links[0].Seq)
	}
	assertChained(t, next.Links)
	if !next.Since.Equal(dropped.Since) {
		t.Errorf("Since = %v, want the dropped window's start %v", next.Since, dropped.Since)
	}
}

// Returning an empty snapshot is a no-op, so the ticker can call it
// unconditionally on the drop path.
func TestReturnWindow_EmptySnapshotIsNoop(t *testing.T) {
	t.Parallel()
	w, err := OpenChain(filepath.Join(t.TempDir(), "log.chain"))
	if err != nil {
		t.Fatalf("OpenChain: %v", err)
	}
	defer w.Close()

	first := w.SnapshotAndReset()
	before := time.Now()
	w.ReturnWindow(ChainSummarySnapshot{})
	next := w.SnapshotAndReset()

	if next.Count != 0 || len(next.Links) != 0 {
		t.Errorf("empty return mutated the window: count=%d links=%d", next.Count, len(next.Links))
	}
	if next.Since.Before(first.ObservedAt) || next.Since.After(before.Add(time.Second)) {
		t.Errorf("empty return moved Since: %v", next.Since)
	}
}

// A nil writer must stay nil-safe on the new entry points too — the
// agent runs with the chain disabled in some configs.
func TestChainLinks_NilWriterSafe(t *testing.T) {
	t.Parallel()
	var w *ChainWriter
	w.ReturnWindow(ChainSummarySnapshot{Count: 1, Links: []ChainLink{{Seq: 1}}})
	if snap := w.SnapshotAndReset(); len(snap.Links) != 0 {
		t.Error("nil writer produced links")
	}
}
