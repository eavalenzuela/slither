// Phase 7 / ADR-0042 — record-level chain verification.
//
// Phase 6 #112 (chain.go) could only compare COUNTS, because the
// agent's per-record hash covers a local wall-clock `ts` the server
// cannot reconstruct. That leaves edit-then-relink invisible: rewrite
// one record, recompute its record_hash, re-link everything after it,
// and the file self-verifies at an unchanged length.
//
// ADR-0042 does not try to recompute the hash. It makes the server a
// WITNESS. The agent ships each record's (seq, kind, prev_hash,
// record_hash) tuple; the server stores them append-only in
// pg.chain_links and checks three properties per segment:
//
//  1. Internal linkage — seq increments by one and prev_hash[i]
//     equals record_hash[i-1]. A seq=0 link must anchor on zeroHash.
//  2. Continuity — the first link past the witness must chain onto
//     the newest record_hash the server already holds.
//  3. Immutability — a seq the server has already witnessed must be
//     re-reported under the identical record_hash.
//
// (3) catches the edit directly when the agent re-reports the window
// after a restart; (2) catches it in the general case, because
// relinking necessarily changes every record_hash after the edit,
// including the tail the next segment chains onto. Either way the
// attacker's window shrinks from "any time before the audit" to "less
// than one summary interval".
//
// What this still does NOT do: prove a record's CONTENT matches its
// hash. The server never sees the record body, only its hash. An
// attacker who edits a record and does NOT relink is caught by the
// on-agent `slither-agent verify-chain` instead. The two checks are
// complementary by construction, and neither defends against an
// attacker who owns the host before the record is first shipped —
// that remains the explicit ADR-0042 / Phase 5 #95 non-goal.

package detect

import (
	"context"
	"fmt"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// Link verification outcomes, mirroring the CHECK constraint on
// chain_summaries.link_status added in migration 00024.
const (
	// LinkStatusNone — the agent shipped no links. A pre-ADR-0042
	// agent, which degrades cleanly to count-only verification.
	LinkStatusNone = "none"
	// LinkStatusOK — the segment replayed clean and chained onto the
	// witness.
	LinkStatusOK = "ok"
	// LinkStatusTruncated — the agent's bounded link buffer overflowed.
	// The tail is intact (that is what the buffer preserves), so
	// forward continuity holds; the head of the window is missing by
	// design.
	LinkStatusTruncated = "truncated"
	// LinkStatusGap — a sequence hole between the witness and this
	// segment that truncation does not explain. Informational: the
	// links present are internally valid, they just do not abut what
	// the server already holds.
	LinkStatusGap = "gap"
	// LinkStatusBroken — a linkage violation or a contradicted
	// record_hash. This is the tamper signal.
	LinkStatusBroken = "broken"
)

// zeroHash is the sentinel prev_hash the agent writes for seq=0. Kept
// as a literal rather than imported: the server module must not depend
// on the agent module, and the value is part of the wire contract, so
// a divergence here is a contract break the tests pin.
const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ChainLinkStore is the verifier's view of the pg link witness.
//
// Deliberately append-only: there is no update method, because the
// whole guarantee rests on the server refusing to revise a link it has
// already recorded.
type ChainLinkStore interface {
	LatestChainLink(ctx context.Context, hostID string) (pg.ChainLinkRow, bool, error)
	ChainLinkHashesInRange(ctx context.Context, hostID string, lo, hi uint64) (map[uint64]string, error)
	AppendChainLinks(ctx context.Context, hostID string, links []pg.ChainLinkRow) (int, error)
}

// linkResult is the verifier's per-segment finding, folded onto the
// chain_summaries row and (when broken) into an audit entry.
type linkResult struct {
	Status   string
	Detail   string
	Reported uint64
	New      uint64
}

// verifyLinks replays one segment against the witness. It returns a
// result for recording rather than an error for anything the agent
// did; errors are reserved for infrastructure failure, so a tampered
// chain never tears down the agent's session — it gets recorded and
// audited, which is the whole point.
func (v *ChainVerifier) verifyLinks(ctx context.Context, hostID string, summary *pb.ChainSummary) (linkResult, error) {
	links := summary.GetLinks()
	if len(links) == 0 {
		return linkResult{Status: LinkStatusNone}, nil
	}
	res := linkResult{Reported: uint64(len(links))}

	// (1) Internal linkage. Checked before touching the database: a
	// segment that is not self-consistent is never worth a round trip,
	// and must never be persisted.
	if broke := checkSegmentLinkage(links); broke != "" {
		res.Status = LinkStatusBroken
		res.Detail = broke
		return res, nil
	}

	if v.links == nil {
		// Link store not wired (dev config, or a deployment that has
		// not run migration 00024). Report what arrived and verify
		// only what needs no state, rather than claiming "ok".
		res.Status = LinkStatusNone
		res.Detail = "link store not configured; internal linkage verified, witness skipped"
		return res, nil
	}

	loSeq := links[0].GetSeq()
	hiSeq := links[len(links)-1].GetSeq()

	witness, haveWitness, err := v.links.LatestChainLink(ctx, hostID)
	if err != nil {
		return res, fmt.Errorf("chain.verifyLinks: witness: %w", err)
	}

	// (3) Immutability. Any overlap with what we already hold must
	// agree exactly. This is the check that makes the witness
	// meaningful — without it a re-report would silently overwrite
	// history via ON CONFLICT semantics.
	if haveWitness && loSeq <= witness.Seq {
		held, herr := v.links.ChainLinkHashesInRange(ctx, hostID, loSeq, hiSeq)
		if herr != nil {
			return res, fmt.Errorf("chain.verifyLinks: overlap: %w", herr)
		}
		for _, l := range links {
			prior, ok := held[l.GetSeq()]
			if ok && prior != l.GetRecordHash() {
				res.Status = LinkStatusBroken
				res.Detail = fmt.Sprintf(
					"record_hash contradiction at seq=%d: witnessed %s, now reported %s",
					l.GetSeq(), prior, l.GetRecordHash())
				return res, nil
			}
		}
	}

	// (2) Continuity onto the witness.
	switch {
	case !haveWitness:
		// First segment ever for this host. If it starts at seq=0 the
		// zeroHash anchor was already checked in (1). If it starts
		// later, the agent enrolled with a pre-existing chain — real
		// and legitimate (re-enrolment against a rebuilt server), so
		// it anchors here rather than being reported as tampering.
		res.Status = LinkStatusOK
		if loSeq != 0 {
			res.Status = LinkStatusGap
			res.Detail = fmt.Sprintf(
				"no prior witness; anchoring at seq=%d (pre-existing chain)", loSeq)
		}
	case loSeq <= witness.Seq:
		// Overlapping re-report — the restart backfill path. Already
		// reconciled by (3); nothing to anchor.
		res.Status = LinkStatusOK
	case loSeq == witness.Seq+1:
		if links[0].GetPrevHash() != witness.RecordHash {
			res.Status = LinkStatusBroken
			res.Detail = fmt.Sprintf(
				"continuity break at seq=%d: prev_hash %s does not chain onto witnessed record_hash %s",
				loSeq, links[0].GetPrevHash(), witness.RecordHash)
			return res, nil
		}
		res.Status = LinkStatusOK
	default:
		// loSeq > witness.Seq+1 — a hole. Truncation explains it when
		// the agent said so; otherwise it is an unexplained hole and
		// the operator should see it.
		if summary.GetLinksTruncated() {
			res.Status = LinkStatusTruncated
			res.Detail = fmt.Sprintf(
				"agent link buffer overflowed; window head dropped, witness at seq=%d, segment starts at seq=%d",
				witness.Seq, loSeq)
		} else {
			res.Status = LinkStatusGap
			res.Detail = fmt.Sprintf(
				"sequence hole: witness at seq=%d, segment starts at seq=%d",
				witness.Seq, loSeq)
		}
	}

	// Persist. Only reached when nothing is broken — a broken segment
	// returns above and writes nothing, so contradicted data can never
	// enter the witness.
	rows := make([]pg.ChainLinkRow, 0, len(links))
	for _, l := range links {
		rows = append(rows, pg.ChainLinkRow{
			HostID:     hostID,
			Seq:        l.GetSeq(),
			Kind:       l.GetKind(),
			PrevHash:   l.GetPrevHash(),
			RecordHash: l.GetRecordHash(),
		})
	}
	n, err := v.links.AppendChainLinks(ctx, hostID, rows)
	if err != nil {
		return res, fmt.Errorf("chain.verifyLinks: append: %w", err)
	}
	res.New = uint64(n)
	return res, nil
}

// checkSegmentLinkage validates a segment in isolation: ascending
// contiguous seq, prev_hash chaining, a zeroHash anchor at seq=0, and
// no empty hashes. Returns "" when clean, else the reason.
func checkSegmentLinkage(links []*pb.ChainLink) string {
	for i, l := range links {
		if l == nil {
			return fmt.Sprintf("nil link at index %d", i)
		}
		if l.GetRecordHash() == "" {
			return fmt.Sprintf("empty record_hash at seq=%d", l.GetSeq())
		}
		if l.GetPrevHash() == "" {
			return fmt.Sprintf("empty prev_hash at seq=%d", l.GetSeq())
		}
		if i == 0 {
			if l.GetSeq() == 0 && l.GetPrevHash() != zeroHash {
				return fmt.Sprintf(
					"seq=0 must anchor on the zero sentinel, got prev_hash %s", l.GetPrevHash())
			}
			continue
		}
		prev := links[i-1]
		if l.GetSeq() != prev.GetSeq()+1 {
			return fmt.Sprintf(
				"non-contiguous seq inside segment: %d follows %d", l.GetSeq(), prev.GetSeq())
		}
		if l.GetPrevHash() != prev.GetRecordHash() {
			return fmt.Sprintf(
				"linkage break at seq=%d: prev_hash %s != preceding record_hash %s",
				l.GetSeq(), l.GetPrevHash(), prev.GetRecordHash())
		}
	}
	return ""
}

// auditLinkBreak fires the `chain.link_mismatch` row. Severity 5
// (critical) rather than the count check's 4: a count delta has benign
// explanations (batch flush lag, clock skew), a contradicted hash does
// not.
func (v *ChainVerifier) auditLinkBreak(ctx context.Context, hostID, rowID string, summary *pb.ChainSummary, res linkResult) {
	_ = v.pg.LogAudit(ctx, pg.AuditEntry{
		ActorType:  pg.ActorAgent,
		ActorID:    hostID,
		Action:     "chain.link_mismatch",
		TargetKind: "chain_summary",
		TargetID:   rowID,
		Detail: map[string]any{
			"host_id":         hostID,
			"last_seq":        summary.GetLastSeq(),
			"links_reported":  res.Reported,
			"link_status":     res.Status,
			"link_detail":     res.Detail,
			"links_truncated": summary.GetLinksTruncated(),
			"observed_at":     summary.GetObservedAt().AsTime().Format(time.RFC3339Nano),
			"severity":        5,
		},
	})
}
