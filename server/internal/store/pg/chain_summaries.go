package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ChainSummaryRow is one chain_summaries table row. Phase 6 #112.
// The console's /hosts/{id}/chain-status page renders these newest-
// first; the verifier writes them on every received ChainSummary.
type ChainSummaryRow struct {
	ID            string
	HostID        string
	LastSeq       uint64
	LastHash      string
	CountObserved uint64
	CountExpected uint64
	Mismatch      bool
	SinceAt       time.Time
	ObservedAt    time.Time
	ReceivedAt    time.Time
}

// ChainSummaryInsert carries the verifier's terminal computation.
// Both counts + the mismatch flag arrive together so the writer can
// commit the row in one round trip.
type ChainSummaryInsert struct {
	HostID        string
	LastSeq       uint64
	LastHash      string
	CountObserved uint64
	CountExpected uint64
	Mismatch      bool
	SinceAt       time.Time
	ObservedAt    time.Time
}

// RecordChainSummary writes one row. Phase 6 #112. Returns the
// generated row id so the verifier's audit-log entry can reference it.
func (s *Store) RecordChainSummary(ctx context.Context, in ChainSummaryInsert) (string, error) {
	hostUUID, err := parseUUID(in.HostID)
	if err != nil {
		return "", fmt.Errorf("pg.RecordChainSummary: parse host_id: %w", err)
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO chain_summaries (
			host_id, last_seq, last_hash,
			count_observed, count_expected, mismatch,
			since_at, observed_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`,
		hostUUID,
		int64(in.LastSeq), in.LastHash,
		int64(in.CountObserved), int64(in.CountExpected), in.Mismatch,
		in.SinceAt, in.ObservedAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("pg.RecordChainSummary: %w", err)
	}
	return id, nil
}

// ListChainSummaries returns the most recent N rows for one host,
// newest first. limit is clamped to [1, 200] so the console doesn't
// accidentally pull a year of summaries on a typo.
func (s *Store) ListChainSummaries(ctx context.Context, hostID string, limit int) ([]ChainSummaryRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainSummaries: parse host_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, host_id, last_seq, last_hash,
		       count_observed, count_expected, mismatch,
		       since_at, observed_at, received_at
		FROM chain_summaries
		WHERE host_id = $1
		ORDER BY received_at DESC
		LIMIT $2
	`, hostUUID, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainSummaries: %w", err)
	}
	defer rows.Close()
	var out []ChainSummaryRow
	for rows.Next() {
		var r ChainSummaryRow
		var lastSeq, countObs, countExp int64
		if err := rows.Scan(
			&r.ID, &r.HostID, &lastSeq, &r.LastHash,
			&countObs, &countExp, &r.Mismatch,
			&r.SinceAt, &r.ObservedAt, &r.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("pg.ListChainSummaries: scan: %w", err)
		}
		r.LastSeq = uint64(lastSeq)
		r.CountObserved = uint64(countObs)
		r.CountExpected = uint64(countExp)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListChainMismatches returns only the mismatched summaries for a
// host, newest first. Phase 6 #112.
func (s *Store) ListChainMismatches(ctx context.Context, hostID string, limit int) ([]ChainSummaryRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainMismatches: parse host_id: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, host_id, last_seq, last_hash,
		       count_observed, count_expected, mismatch,
		       since_at, observed_at, received_at
		FROM chain_summaries
		WHERE host_id = $1 AND mismatch = true
		ORDER BY received_at DESC
		LIMIT $2
	`, hostUUID, limit)
	if err != nil {
		return nil, fmt.Errorf("pg.ListChainMismatches: %w", err)
	}
	defer rows.Close()
	var out []ChainSummaryRow
	for rows.Next() {
		var r ChainSummaryRow
		var lastSeq, countObs, countExp int64
		if err := rows.Scan(
			&r.ID, &r.HostID, &lastSeq, &r.LastHash,
			&countObs, &countExp, &r.Mismatch,
			&r.SinceAt, &r.ObservedAt, &r.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("pg.ListChainMismatches: scan: %w", err)
		}
		r.LastSeq = uint64(lastSeq)
		r.CountObserved = uint64(countObs)
		r.CountExpected = uint64(countExp)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountResponseActionsForChain returns the number of response_actions
// rows for one host whose terminal state landed in [since, until).
// Used by the chain verifier to compute count_expected. Phase 6 #112.
//
// "Terminal state" means status in (done, failed) — the agent's chain
// only appends a record_hash on terminal transitions, so pending /
// running rows have no chain equivalent.
func (s *Store) CountResponseActionsForChain(ctx context.Context, hostID string, since, until time.Time) (uint64, error) {
	hostUUID, err := parseUUID(hostID)
	if err != nil {
		return 0, fmt.Errorf("pg.CountResponseActionsForChain: parse host_id: %w", err)
	}
	var n int64
	err = s.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM response_actions
		WHERE host_id = $1
		  AND status IN ('done', 'failed')
		  AND completed_at IS NOT NULL
		  AND completed_at >= $2
		  AND completed_at <  $3
	`, hostUUID, since, until).Scan(&n)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("pg.CountResponseActionsForChain: %w", err)
	}
	if n < 0 {
		return 0, nil
	}
	return uint64(n), nil
}
