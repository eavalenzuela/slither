// Package-internal Phase 6 #112 chain summary verifier.
//
// The agent's selfprotect.ChainWriter ticks one ChainSummary
// {last_seq, last_hash, count, since, observed_at} every 5 minutes
// on a healthy host. This verifier:
//
//  1. counts equivalent rows in pg.response_actions +
//     ClickHouse ocsf_detection_finding_2004 for (host_id,
//     [since, observed_at)),
//  2. compares the server-side total against the agent-reported
//     count,
//  3. records the summary in pg.chain_summaries (one row per
//     received summary, with a `mismatch` boolean),
//  4. fires a `chain.mismatch` audit row on divergence.
//
// last_hash is stored verbatim. The server still does NOT recompute
// it — the agent's per-record hash includes a wall-clock TS the server
// can't reconstruct, and ADR-0042 deliberately keeps it hashed so
// on-agent back-dating stays detectable.
//
// Phase 7 / ADR-0042 closed the §9 carry-over by making the server a
// link WITNESS instead: chain_links.go replays each summary's shipped
// (seq, kind, prev_hash, record_hash) tuples against what the server
// already holds, which catches the record-level edit this count check
// cannot. Both checks run on every summary and are recorded on the
// same row — they fail independently and mean different things.
//
// Skew tolerance: the agent's clock can drift relative to the server
// + the [since, observed_at) bounds describe agent-local time. The
// verifier accepts a small absolute count delta (skewSlack) before
// declaring mismatch — covers events the server has not yet flushed
// from CH's batch buffer at summary-receive time. SkewSlack is
// configurable; default 1.

package detect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	chstore "github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// ChainStore is the verifier's view of pg. Decoupled so tests can
// pass an in-memory stub without spinning a testcontainer.
type ChainStore interface {
	CountResponseActionsForChain(ctx context.Context, hostID string, since, until time.Time) (uint64, error)
	RecordChainSummary(ctx context.Context, in pg.ChainSummaryInsert) (string, error)
	LogAudit(ctx context.Context, entry pg.AuditEntry) error
}

// ChainCHStore is the verifier's view of ClickHouse. Optional —
// when nil, the verifier compares only against pg.response_actions
// (used in tests + dev configs without CH).
type ChainCHStore interface {
	CountDetectionFindingsForChain(ctx context.Context, hostID string, since, until time.Time) (uint64, error)
}

// ChainVerifierOptions tunes the verifier. Defaults are good for
// production; tests override SkewSlack to assert exact equality.
type ChainVerifierOptions struct {
	// SkewSlack is the absolute count delta the verifier accepts
	// before declaring mismatch. Default 1 — covers a single CH-batch
	// flush race where one row hasn't landed yet by the time the
	// summary arrives.
	SkewSlack uint64
}

// ChainVerifier is the concrete grpcserv.ChainVerifier impl.
type ChainVerifier struct {
	pg    ChainStore
	ch    ChainCHStore
	links ChainLinkStore
	opts  ChainVerifierOptions
}

// NewChainVerifier wires the verifier. ch may be nil — the verifier
// then compares only pg counts.
//
// The ADR-0042 link witness is picked up by capability upgrade: the
// real *pg.Store implements ChainLinkStore, and the assertion below
// makes that a compile-time guarantee rather than a runtime hope. A
// store that doesn't (a narrow test stub) leaves links nil, and
// verifyLinks records `link_status = none` with a reason instead of
// silently claiming the segment verified.
func NewChainVerifier(pgStore ChainStore, chStore ChainCHStore, opts ChainVerifierOptions) *ChainVerifier {
	v := &ChainVerifier{pg: pgStore, ch: chStore, opts: opts}
	if ls, ok := pgStore.(ChainLinkStore); ok {
		v.links = ls
	}
	return v
}

// The production store must always satisfy the link witness contract;
// dropping a method here is a build failure, not a silent downgrade to
// count-only verification.
var _ ChainLinkStore = (*pg.Store)(nil)

// Verify is the grpcserv.ChainVerifier entry. Returns an error only
// when a hard infrastructure failure prevents the cross-check (pg
// down). Mismatches and CH-down scenarios fold into successful audit
// rows + are not surfaced as errors so the agent's send loop never
// tears down on a chain check.
func (v *ChainVerifier) Verify(ctx context.Context, hostID string, summary *pb.ChainSummary) error {
	if v == nil || v.pg == nil {
		return errors.New("chain: verifier not initialised")
	}
	if summary == nil {
		return errors.New("chain: nil summary")
	}
	since := summary.GetSince().AsTime()
	until := summary.GetObservedAt().AsTime()
	if !until.After(since) {
		// Empty / inverted window — agent emitted before its first
		// real interval. Record the summary verbatim with both counts
		// zeroed so the host page still surfaces "agent reported in"
		// but skip the count-divergence check.
		//
		// Link verification still runs. The count check needs a sane
		// window because it compares against time-bounded rows; the
		// link check is keyed on seq, not time, so an inverted window
		// is no reason to skip the half that detects tampering.
		linkRes, linkErr := v.verifyLinks(ctx, hostID, summary)
		if linkErr != nil {
			return linkErr
		}
		rowID, recErr := v.pg.RecordChainSummary(ctx, pg.ChainSummaryInsert{
			HostID:        hostID,
			LastSeq:       summary.GetLastSeq(),
			LastHash:      summary.GetLastHash(),
			CountObserved: summary.GetCount(),
			CountExpected: 0,
			Mismatch:      linkRes.Status == LinkStatusBroken,
			SinceAt:       since,
			ObservedAt:    until,
			LinksReported: linkRes.Reported,
			LinksNew:      linkRes.New,
			LinkStatus:    linkRes.Status,
			LinkDetail:    linkRes.Detail,
		})
		if recErr != nil {
			return recErr
		}
		if linkRes.Status == LinkStatusBroken {
			v.auditLinkBreak(ctx, hostID, rowID, summary, linkRes)
		}
		return nil
	}

	respCount, err := v.pg.CountResponseActionsForChain(ctx, hostID, since, until)
	if err != nil {
		return fmt.Errorf("chain.Verify: pg count: %w", err)
	}
	var findingCount uint64
	chPresent := false
	if v.ch != nil {
		c, cherr := v.ch.CountDetectionFindingsForChain(ctx, hostID, since, until)
		if cherr != nil {
			// CH error logs + degrades to pg-only count. The audit
			// row's detail captures the degradation so operators can
			// tell apart "real divergence" from "CH was unreachable
			// during this verification window".
			slog.Warn("chain: CH count failed; degrading to pg-only",
				"host_id", hostID, "err", cherr)
		} else {
			findingCount = c
			chPresent = true
		}
	}
	expected := respCount + findingCount
	observed := summary.GetCount()

	countMismatch := absDelta(expected, observed) > v.opts.skewSlack()

	// ADR-0042 record-level pass. Runs regardless of the count result
	// — the two detect different attacks and a clean count is exactly
	// what edit-then-relink produces.
	linkRes, linkErr := v.verifyLinks(ctx, hostID, summary)
	if linkErr != nil {
		return linkErr
	}
	linkBroken := linkRes.Status == LinkStatusBroken

	// One `mismatch` flag covers both checks so existing consumers
	// (ListChainMismatches, the host page's red badge) light up for a
	// link break without needing to know about link_status. The
	// specific reason lives in link_status / link_detail.
	mismatch := countMismatch || linkBroken

	rowID, recErr := v.pg.RecordChainSummary(ctx, pg.ChainSummaryInsert{
		HostID:        hostID,
		LastSeq:       summary.GetLastSeq(),
		LastHash:      summary.GetLastHash(),
		CountObserved: observed,
		CountExpected: expected,
		Mismatch:      mismatch,
		SinceAt:       since,
		ObservedAt:    until,
		LinksReported: linkRes.Reported,
		LinksNew:      linkRes.New,
		LinkStatus:    linkRes.Status,
		LinkDetail:    linkRes.Detail,
	})
	if recErr != nil {
		return fmt.Errorf("chain.Verify: record: %w", recErr)
	}

	if linkBroken {
		v.auditLinkBreak(ctx, hostID, rowID, summary, linkRes)
	}

	if countMismatch {
		// `chain.mismatch` audit row at severity 4 (high). Surfaced
		// in the audit log + the host's chain-status page. No new
		// alert class — this is operator-attention-only.
		_ = v.pg.LogAudit(ctx, pg.AuditEntry{
			ActorType:  pg.ActorAgent,
			ActorID:    hostID,
			Action:     "chain.mismatch",
			TargetKind: "chain_summary",
			TargetID:   rowID,
			Detail: map[string]any{
				"host_id":          hostID,
				"last_seq":         summary.GetLastSeq(),
				"count_observed":   observed,
				"count_expected":   expected,
				"since":            since.Format(time.RFC3339Nano),
				"observed_at":      until.Format(time.RFC3339Nano),
				"severity":         4,
				"ch_count_present": chPresent,
				"link_status":      linkRes.Status,
			},
		})
	}
	return nil
}

func (o ChainVerifierOptions) skewSlack() uint64 {
	if o.SkewSlack == 0 {
		return 1
	}
	return o.SkewSlack
}

// absDelta returns |a-b| without overflowing on uint subtraction.
func absDelta(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// Compile-time assertion that *ChainVerifier satisfies the
// grpcserv.ChainVerifier interface contract. Asserted via a blank
// var so adding a method to the interface fails the build here
// rather than at the SessionService wiring site.
var _ interface {
	Verify(ctx context.Context, hostID string, summary *pb.ChainSummary) error
} = (*ChainVerifier)(nil)

// ch type alias keeps the import surface localised; ChainCHStore names
// it above so other server packages reading this file see the
// dependency contract. The pg side is pinned by the ChainLinkStore
// assertion further up.
type _ = chstore.Store
