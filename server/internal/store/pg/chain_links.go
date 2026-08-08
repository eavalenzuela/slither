package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ChainLinkRow is one witnessed hash-chain link. Phase 7 / ADR-0042.
//
// Rows are append-only by contract: the verifier inserts with
// ON CONFLICT DO NOTHING and compares against what it already holds
// rather than updating. There is deliberately no update method on this
// type — the whole point of the witness is that a compromised agent
// cannot revise history it has already reported.
type ChainLinkRow struct {
	HostID      string
	Seq         uint64
	Kind        string
	PrevHash    string
	RecordHash  string
	FirstSeenAt time.Time
}

// LatestChainLink returns the newest link witnessed for one host —
// the anchor the next segment's prev_hash must chain onto. ok is false
// when the host has no witness yet (first summary after enrolment, or
// a pre-ADR-0042 agent that never shipped links).
func (s *Store) LatestChainLink(ctx context.Context, hostID string) (ChainLinkRow, bool, error) {
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return ChainLinkRow{}, false, fmt.Errorf("pg.LatestChainLink: parse host_id: %w", err)
	}
	var (
		r   ChainLinkRow
		seq int64
	)
	// (host_id, seq) is the primary key, so this is a one-row backward
	// index scan rather than a sort.
	err = s.pool.QueryRow(ctx, `
		SELECT seq, kind, prev_hash, record_hash, first_seen_at
		FROM chain_links
		WHERE host_id = $1
		ORDER BY seq DESC
		LIMIT 1
	`, hostUUID).Scan(&seq, &r.Kind, &r.PrevHash, &r.RecordHash, &r.FirstSeenAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ChainLinkRow{}, false, nil
		}
		return ChainLinkRow{}, false, fmt.Errorf("pg.LatestChainLink: %w", err)
	}
	r.HostID = hostID
	r.Seq = uint64(seq)
	return r, true, nil
}

// ChainLinkHashesInRange returns the record_hash the server already
// holds for each seq in [lo, hi] for one host. The verifier uses it to
// detect a contradiction — the same seq re-reported under a different
// hash, which is what edit-then-relink produces.
//
// An empty map means "nothing witnessed in that range", which is the
// normal case for a fresh segment.
func (s *Store) ChainLinkHashesInRange(ctx context.Context, hostID string, lo, hi uint64) (map[uint64]string, error) {
	if hi < lo {
		return map[uint64]string{}, nil
	}
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return nil, fmt.Errorf("pg.ChainLinkHashesInRange: parse host_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, record_hash
		FROM chain_links
		WHERE host_id = $1 AND seq >= $2 AND seq <= $3
	`, hostUUID, int64(lo), int64(hi))
	if err != nil {
		return nil, fmt.Errorf("pg.ChainLinkHashesInRange: %w", err)
	}
	defer rows.Close()
	out := make(map[uint64]string)
	for rows.Next() {
		var (
			seq  int64
			hash string
		)
		if err := rows.Scan(&seq, &hash); err != nil {
			return nil, fmt.Errorf("pg.ChainLinkHashesInRange: scan: %w", err)
		}
		out[uint64(seq)] = hash
	}
	return out, rows.Err()
}

// AppendChainLinks witnesses a batch of links, skipping any seq already
// held. Returns the number of genuinely new rows — the verifier records
// it on the summary so an operator can tell a fresh segment from a
// restart's re-report at a glance.
//
// One round trip: the batch is unnested server-side rather than looped,
// because a burst window can carry the full 512-link buffer and 512
// sequential round trips on the session's hot path is not acceptable.
func (s *Store) AppendChainLinks(ctx context.Context, hostID string, links []ChainLinkRow) (int, error) {
	if len(links) == 0 {
		return 0, nil
	}
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return 0, fmt.Errorf("pg.AppendChainLinks: parse host_id: %w", err)
	}
	seqs := make([]int64, len(links))
	kinds := make([]string, len(links))
	prevs := make([]string, len(links))
	recs := make([]string, len(links))
	for i, l := range links {
		seqs[i] = int64(l.Seq)
		kinds[i] = l.Kind
		prevs[i] = l.PrevHash
		recs[i] = l.RecordHash
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO chain_links (host_id, seq, kind, prev_hash, record_hash)
		SELECT $1, u.seq, u.kind, u.prev_hash, u.record_hash
		FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[])
		     AS u(seq, kind, prev_hash, record_hash)
		ON CONFLICT (host_id, seq) DO NOTHING
	`, hostUUID, seqs, kinds, prevs, recs)
	if err != nil {
		return 0, fmt.Errorf("pg.AppendChainLinks: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListChainLinks returns a host's witnessed links in [fromSeq, ...]
// ascending, capped at limit. Backs the console's chain-status detail
// view and the operator's "show me what the server actually saw"
// question during an incident. limit is clamped to [1, 1000].
func (s *Store) ListChainLinks(ctx context.Context, hostID string, fromSeq uint64, limit int) ([]ChainLinkRow, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainLinks: parse host_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, kind, prev_hash, record_hash, first_seen_at
		FROM chain_links
		WHERE host_id = $1 AND seq >= $2
		ORDER BY seq ASC
		LIMIT $3
	`, hostUUID, int64(fromSeq), limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainLinks: %w", err)
	}
	defer rows.Close()
	var out []ChainLinkRow
	for rows.Next() {
		var (
			r   ChainLinkRow
			seq int64
		)
		if err := rows.Scan(&seq, &r.Kind, &r.PrevHash, &r.RecordHash, &r.FirstSeenAt); err != nil {
			return nil, fmt.Errorf("pg.ListChainLinks: scan: %w", err)
		}
		r.HostID = hostID
		r.Seq = uint64(seq)
		out = append(out, r)
	}
	return out, rows.Err()
}
