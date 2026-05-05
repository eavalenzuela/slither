package ch

import (
	"context"
	"fmt"
	"time"
)

// CountDetectionFindingsForChain returns the number of OCSF
// detection_finding (class 2004) rows for one host whose observed_at
// falls in [since, until). Used by the Phase 6 #112 chain verifier to
// compute count_expected. host_id is parsed as a UUID by the caller
// (pg side); we just bind it as a string and let CH's UUID() coerce.
func (s *Store) CountDetectionFindingsForChain(ctx context.Context, hostID string, since, until time.Time) (uint64, error) {
	if s == nil || s.conn == nil {
		return 0, fmt.Errorf("ch: store not initialised")
	}
	row := s.conn.QueryRow(ctx, `
		SELECT count()
		FROM ocsf_detection_finding_2004
		WHERE host_id = ?
		  AND observed_at >= ?
		  AND observed_at <  ?
	`, hostID, since, until)
	var n uint64
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("ch.CountDetectionFindingsForChain: %w", err)
	}
	return n, nil
}
