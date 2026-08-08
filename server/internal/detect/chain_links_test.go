package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

const testHost = "00000000-0000-4000-8000-0000000000aa"

// hashOf produces a deterministic stand-in for a record_hash. The
// verifier never recomputes hashes — it only compares them — so the
// tests only need values that are distinct and stable.
func hashOf(seq uint64) string {
	return fmt.Sprintf("%064x", seq+1)
}

// chainOf builds a well-formed segment [from, from+n) where each link
// chains onto the previous. seq=0 anchors on zeroHash.
func chainOf(from, n uint64) []*pb.ChainLink {
	out := make([]*pb.ChainLink, 0, n)
	for i := from; i < from+n; i++ {
		prev := zeroHash
		if i > 0 {
			prev = hashOf(i - 1)
		}
		kind := "detection_finding"
		if i == 0 {
			kind = "chain.init"
		}
		out = append(out, &pb.ChainLink{
			Seq:        i,
			Kind:       kind,
			PrevHash:   prev,
			RecordHash: hashOf(i),
		})
	}
	return out
}

func linkSummary(links []*pb.ChainLink, truncated bool) *pb.ChainSummary {
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	var lastSeq uint64
	lastHash := zeroHash
	if len(links) > 0 {
		lastSeq = links[len(links)-1].GetSeq()
		lastHash = links[len(links)-1].GetRecordHash()
	}
	return &pb.ChainSummary{
		LastSeq:        lastSeq,
		LastHash:       lastHash,
		Count:          0,
		Since:          timestamppb.New(since),
		ObservedAt:     timestamppb.New(until),
		Links:          links,
		LinksTruncated: truncated,
	}
}

// seedWitness pre-populates the stub as though the server had already
// witnessed [0, n).
func seedWitness(stub *stubChainStore, n uint64) {
	stub.witness = map[uint64]pg.ChainLinkRow{}
	for _, l := range chainOf(0, n) {
		stub.witness[l.GetSeq()] = pg.ChainLinkRow{
			HostID:     testHost,
			Seq:        l.GetSeq(),
			Kind:       l.GetKind(),
			PrevHash:   l.GetPrevHash(),
			RecordHash: l.GetRecordHash(),
		}
	}
}

func verifyWith(t *testing.T, stub *stubChainStore, sum *pb.ChainSummary) {
	t.Helper()
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	if v.links == nil {
		t.Fatal("capability upgrade failed: verifier has no link store")
	}
	if err := v.Verify(context.Background(), testHost, sum); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A brand-new host's first segment anchors on the zero sentinel and is
// witnessed in full.
func TestVerifyLinks_FirstSegmentAnchorsOnZeroHash(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	verifyWith(t, stub, linkSummary(chainOf(0, 4), false))

	if got := stub.recorded.LinkStatus; got != LinkStatusOK {
		t.Errorf("link_status = %q, want %q (detail: %q)", got, LinkStatusOK, stub.recorded.LinkDetail)
	}
	if stub.recorded.LinksReported != 4 || stub.recorded.LinksNew != 4 {
		t.Errorf("reported/new = %d/%d, want 4/4", stub.recorded.LinksReported, stub.recorded.LinksNew)
	}
	if stub.recorded.Mismatch {
		t.Error("clean segment recorded as mismatch")
	}
	if len(stub.auditEntries) != 0 {
		t.Errorf("clean segment fired %d audit rows", len(stub.auditEntries))
	}
}

// The normal steady-state case: the next segment chains onto the tail
// the server already holds.
func TestVerifyLinks_ContinuesFromWitness(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 5) // witnessed seq 0..4
	verifyWith(t, stub, linkSummary(chainOf(5, 3), false))

	if got := stub.recorded.LinkStatus; got != LinkStatusOK {
		t.Errorf("link_status = %q, want %q (detail: %q)", got, LinkStatusOK, stub.recorded.LinkDetail)
	}
	if stub.recorded.LinksNew != 3 {
		t.Errorf("links_new = %d, want 3", stub.recorded.LinksNew)
	}
}

// The headline case ADR-0042 exists for. The attacker rewrites a
// record and re-links everything after it, so the file still
// self-verifies and the count is unchanged — but the tail no longer
// chains onto what the server witnessed.
func TestVerifyLinks_RelinkedTailBreaksContinuity(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 5)

	// Segment starts at the right seq but its prev_hash reflects a
	// rewritten seq=4 rather than the witnessed one.
	seg := chainOf(5, 2)
	seg[0].PrevHash = strings.Repeat("9", 64)

	verifyWith(t, stub, linkSummary(seg, false))

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusBroken)
	}
	if !stub.recorded.Mismatch {
		t.Error("link break did not set the summary's mismatch flag")
	}
	if !strings.Contains(stub.recorded.LinkDetail, "continuity break at seq=5") {
		t.Errorf("detail = %q, want a continuity-break reason", stub.recorded.LinkDetail)
	}
	if _, held := stub.witness[5]; held {
		t.Error("a broken segment was persisted into the witness")
	}
	if len(stub.auditEntries) != 1 || stub.auditEntries[0].Action != "chain.link_mismatch" {
		t.Fatalf("audit entries = %+v, want one chain.link_mismatch", stub.auditEntries)
	}
	if sev := stub.auditEntries[0].Detail["severity"]; sev != 5 {
		t.Errorf("severity = %v, want 5", sev)
	}
}

// The restart-backfill path re-reports links the server already holds.
// A contradiction there is the most direct tamper signal available.
func TestVerifyLinks_ContradictedHashIsBroken(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 5)

	// Re-report 2..4 but with seq=3 rewritten. Re-link 4 onto it so
	// the segment is internally consistent — exactly what an attacker
	// who relinks produces.
	seg := []*pb.ChainLink{
		{Seq: 2, Kind: "detection_finding", PrevHash: hashOf(1), RecordHash: hashOf(2)},
		{Seq: 3, Kind: "detection_finding", PrevHash: hashOf(2), RecordHash: strings.Repeat("7", 64)},
		{Seq: 4, Kind: "detection_finding", PrevHash: strings.Repeat("7", 64), RecordHash: hashOf(4)},
	}
	verifyWith(t, stub, linkSummary(seg, false))

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusBroken)
	}
	if !strings.Contains(stub.recorded.LinkDetail, "contradiction at seq=3") {
		t.Errorf("detail = %q, want a seq=3 contradiction", stub.recorded.LinkDetail)
	}
	if got := stub.witness[3].RecordHash; got != hashOf(3) {
		t.Errorf("witness at seq=3 was overwritten: %s", got)
	}
}

// A benign restart re-reports an overlapping window verbatim. It must
// verify clean and count only the genuinely new links.
func TestVerifyLinks_RestartOverlapIsClean(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 5)
	verifyWith(t, stub, linkSummary(chainOf(2, 6), false)) // 2..7, of which 5..7 are new

	if got := stub.recorded.LinkStatus; got != LinkStatusOK {
		t.Errorf("link_status = %q, want %q (detail: %q)", got, LinkStatusOK, stub.recorded.LinkDetail)
	}
	if stub.recorded.LinksReported != 6 {
		t.Errorf("links_reported = %d, want 6", stub.recorded.LinksReported)
	}
	if stub.recorded.LinksNew != 3 {
		t.Errorf("links_new = %d, want 3", stub.recorded.LinksNew)
	}
}

// A segment that doesn't chain to itself never reaches the database.
func TestVerifyLinks_InternalLinkageBreakSkipsStore(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 3)
	// Make the store explode if it is touched at all.
	stub.witnessErr = errors.New("must not be called")

	seg := chainOf(3, 3)
	seg[2].PrevHash = strings.Repeat("1", 64)
	verifyWith(t, stub, linkSummary(seg, false))

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusBroken)
	}
	if !strings.Contains(stub.recorded.LinkDetail, "linkage break at seq=5") {
		t.Errorf("detail = %q, want a seq=5 linkage break", stub.recorded.LinkDetail)
	}
}

// Rebuilding the chain from scratch restarts at seq=0. The witness
// already holds a nonzero tail, so the contradiction check catches it.
func TestVerifyLinks_ChainRebuiltFromScratchIsBroken(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 6)

	// Attacker's fresh chain: valid in isolation, different hashes.
	seg := []*pb.ChainLink{
		{Seq: 0, Kind: "chain.init", PrevHash: zeroHash, RecordHash: strings.Repeat("a", 64)},
		{Seq: 1, Kind: "detection_finding", PrevHash: strings.Repeat("a", 64), RecordHash: strings.Repeat("b", 64)},
	}
	verifyWith(t, stub, linkSummary(seg, false))

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q (detail %q)", got, LinkStatusBroken, stub.recorded.LinkDetail)
	}
}

// A seq=0 link that does not anchor on the zero sentinel is malformed.
func TestVerifyLinks_SeqZeroMustAnchorOnZeroHash(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seg := chainOf(0, 2)
	seg[0].PrevHash = strings.Repeat("c", 64)
	verifyWith(t, stub, linkSummary(seg, false))

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusBroken)
	}
	if !strings.Contains(stub.recorded.LinkDetail, "zero sentinel") {
		t.Errorf("detail = %q, want the zero-sentinel reason", stub.recorded.LinkDetail)
	}
}

// An unexplained hole is informational, not a tamper verdict — but it
// is still recorded and the links are still witnessed.
func TestVerifyLinks_UnexplainedHoleIsGap(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 3) // 0..2
	verifyWith(t, stub, linkSummary(chainOf(9, 2), false))

	if got := stub.recorded.LinkStatus; got != LinkStatusGap {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusGap)
	}
	if stub.recorded.Mismatch {
		t.Error("a gap must not set the mismatch flag — restarts are normal")
	}
	if len(stub.auditEntries) != 0 {
		t.Errorf("a gap fired %d audit rows, want 0", len(stub.auditEntries))
	}
	if _, ok := stub.witness[9]; !ok {
		t.Error("gap segment was not witnessed")
	}
}

// The same hole, explained by the agent's truncation flag, is reported
// as truncation so the operator isn't sent hunting for a deletion.
func TestVerifyLinks_TruncatedFlagExplainsHole(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 3)
	verifyWith(t, stub, linkSummary(chainOf(9, 2), true))

	if got := stub.recorded.LinkStatus; got != LinkStatusTruncated {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusTruncated)
	}
	if stub.recorded.Mismatch {
		t.Error("truncation must not set the mismatch flag")
	}
}

// A pre-ADR-0042 agent ships no links. That must degrade to the
// Phase 6 #112 behaviour exactly, not look like tampering.
func TestVerifyLinks_NoLinksDegradesToCountOnly(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 2, findingCount: 1}
	since := time.Now().Add(-5 * time.Minute).UTC()
	until := time.Now().UTC()
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	if err := v.Verify(context.Background(), testHost, mkSummary(3, since, until)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := stub.recorded.LinkStatus; got != LinkStatusNone {
		t.Errorf("link_status = %q, want %q", got, LinkStatusNone)
	}
	if stub.recorded.Mismatch {
		t.Error("a link-less summary with matching counts was flagged")
	}
}

// A link break must flag the row even when the count check is happy —
// that combination is precisely what edit-then-relink produces.
func TestVerifyLinks_BreakFlagsRowDespiteMatchingCounts(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{respCount: 1, findingCount: 1}
	seedWitness(stub, 4)

	seg := chainOf(4, 2)
	seg[0].PrevHash = strings.Repeat("e", 64)
	sum := linkSummary(seg, false)
	sum.Count = 2 // counts agree exactly

	verifyWith(t, stub, sum)

	if !stub.recorded.Mismatch {
		t.Error("mismatch flag not set on a link break with clean counts")
	}
	if stub.recorded.CountObserved != stub.recorded.CountExpected {
		t.Fatalf("test setup wrong: counts differ (%d vs %d)",
			stub.recorded.CountObserved, stub.recorded.CountExpected)
	}
	if len(stub.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want exactly the link one", len(stub.auditEntries))
	}
}

// An inverted window skips the count comparison but must still verify
// links — the link check is keyed on seq, not time.
func TestVerifyLinks_InvertedWindowStillVerifies(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{}
	seedWitness(stub, 4)

	seg := chainOf(4, 2)
	seg[0].PrevHash = strings.Repeat("d", 64)
	sum := linkSummary(seg, false)
	now := time.Now().UTC()
	sum.Since = timestamppb.New(now)
	sum.ObservedAt = timestamppb.New(now) // not After → inverted

	verifyWith(t, stub, sum)

	if got := stub.recorded.LinkStatus; got != LinkStatusBroken {
		t.Fatalf("link_status = %q, want %q", got, LinkStatusBroken)
	}
	if len(stub.auditEntries) != 1 {
		t.Errorf("audit entries = %d, want 1", len(stub.auditEntries))
	}
}

// A store failure during link verification is infrastructure, not
// tampering: it surfaces as an error rather than a false accusation.
func TestVerifyLinks_StoreErrorSurfaces(t *testing.T) {
	t.Parallel()
	stub := &stubChainStore{appendErr: errors.New("pg down")}
	v := NewChainVerifier(stub, stub, ChainVerifierOptions{})
	err := v.Verify(context.Background(), testHost, linkSummary(chainOf(0, 2), false))
	if err == nil {
		t.Fatal("Verify returned nil on an append failure")
	}
	if len(stub.auditEntries) != 0 {
		t.Error("an infrastructure failure fired a tamper audit row")
	}
}
