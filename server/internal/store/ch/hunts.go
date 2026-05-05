package ch

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// HuntResultRow projects one row out of the hunt_results table for the
// console's detail page. observed_at is server insertion time, not the
// extension's collection time — extensions today don't stamp a per-row
// timestamp.
type HuntResultRow struct {
	HostID     string
	ObservedAt time.Time
	Columns    []string
	Values     []string
}

// InsertHuntResults appends a batch of rows for one (queryID, hostID).
// Each (cols, vals) pair is one CH row. Caller batches per-extension
// chunk; this method runs a prepared insert per call so a slow CH
// flush doesn't stall the agent's HuntResult Recv goroutine.
func (s *Store) InsertHuntResults(ctx context.Context, queryID, hostID string, cols [][]string, vals [][]string) error {
	if len(cols) != len(vals) {
		return errors.New("ch.InsertHuntResults: columns/values length mismatch")
	}
	if len(cols) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO hunt_results (query_id, host_id, columns, values)")
	if err != nil {
		return fmt.Errorf("ch.InsertHuntResults: prepare: %w", err)
	}
	for i := range cols {
		if err := batch.Append(queryID, hostID, cols[i], vals[i]); err != nil {
			return fmt.Errorf("ch.InsertHuntResults: append row %d: %w", i, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("ch.InsertHuntResults: send: %w", err)
	}
	return nil
}

// ListHuntResults returns rows for a given hunt, ordered by host then
// observed_at. limit caps total rows returned; the console paginates
// with offset (cheap because the partition is daily and the row count
// is bounded by per-host max_rows).
func (s *Store) ListHuntResults(ctx context.Context, queryID string, limit, offset int) ([]HuntResultRow, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	const sql = `
        SELECT toString(host_id) AS host_id,
               observed_at,
               columns,
               values
          FROM hunt_results
         WHERE query_id = ?
         ORDER BY host_id, observed_at, columns
         LIMIT ? OFFSET ?`
	rows, err := s.conn.Query(ctx, sql, queryID, uint64(limit), uint64(offset))
	if err != nil {
		return nil, fmt.Errorf("ch.ListHuntResults: %w", err)
	}
	defer rows.Close()
	var out []HuntResultRow
	for rows.Next() {
		var r HuntResultRow
		if err := rows.Scan(&r.HostID, &r.ObservedAt, &r.Columns, &r.Values); err != nil {
			return nil, fmt.Errorf("ch.ListHuntResults: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountHuntResultsPerHost groups rows by host for the detail page's
// per-host summary panel. Returns map[hostID]rowCount.
func (s *Store) CountHuntResultsPerHost(ctx context.Context, queryID string) (map[string]uint64, error) {
	const sql = `
        SELECT toString(host_id) AS host_id, count() AS n
          FROM hunt_results
         WHERE query_id = ?
         GROUP BY host_id`
	rows, err := s.conn.Query(ctx, sql, queryID)
	if err != nil {
		return nil, fmt.Errorf("ch.CountHuntResultsPerHost: %w", err)
	}
	defer rows.Close()
	out := make(map[string]uint64)
	for rows.Next() {
		var host string
		var n uint64
		if err := rows.Scan(&host, &n); err != nil {
			return nil, fmt.Errorf("ch.CountHuntResultsPerHost: scan: %w", err)
		}
		out[host] = n
	}
	return out, rows.Err()
}
