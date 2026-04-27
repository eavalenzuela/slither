package ch

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// ReplayEnvelopes streams every event row from the table for classUID
// whose observed_at falls in [since, until], ascending so the
// detection engine's bounded-stateful window builds in event-time
// order. Each row is reconstituted into a *pb.Envelope (the same wire
// shape live events ride) and handed to fn one at a time. Returning
// a non-nil error from fn aborts the iteration with that error.
//
// Phase 3 #59 cold-start: detect.Engine calls this for stateful rules
// declared `lookback: true` so they fire on past events as soon as
// the rule is loaded, rather than waiting for the live stream to
// re-accumulate the window.
//
// classUID 0 is treated as an error rather than "every class" — the
// caller is always plan-scoped, and a stray zero usually means a
// missing field rather than fan-in intent.
func (s *Store) ReplayEnvelopes(
	ctx context.Context,
	classUID uint32,
	since, until time.Time,
	fn func(*pb.Envelope) error,
) error {
	if classUID == 0 {
		return fmt.Errorf("ch.ReplayEnvelopes: class_uid required")
	}
	if fn == nil {
		return fmt.Errorf("ch.ReplayEnvelopes: nil callback")
	}
	table, ok := classTables[classUID]
	if !ok {
		return fmt.Errorf("ch.ReplayEnvelopes: unknown class_uid %d", classUID)
	}
	if since.IsZero() || until.IsZero() || !until.After(since) {
		return fmt.Errorf("ch.ReplayEnvelopes: invalid window [%s, %s]", since, until)
	}

	// Bind timestamps as int64 nanos with fromUnixTimestamp64Nano on
	// the SQL side — same trick SearchEvents uses to dodge clickhouse-
	// go's positional-binder DateTime64 quirks.
	stmt := fmt.Sprintf(`
		SELECT
			toString(event_id) AS event_id,
			toString(host_id)  AS host_id,
			class_uid,
			observed_at,
			collected_at,
			raw
		FROM %s
		WHERE observed_at >= fromUnixTimestamp64Nano(?)
		  AND observed_at <= fromUnixTimestamp64Nano(?)
		ORDER BY observed_at ASC, event_id ASC
	`, table)

	rows, err := s.conn.Query(ctx, stmt, since.UnixNano(), until.UnixNano())
	if err != nil {
		return fmt.Errorf("ch.ReplayEnvelopes: query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			eventID     string
			hostID      string
			classUIDOut uint32
			observedAt  time.Time
			collectedAt time.Time
			raw         string
		)
		if err := rows.Scan(&eventID, &hostID, &classUIDOut, &observedAt, &collectedAt, &raw); err != nil {
			return fmt.Errorf("ch.ReplayEnvelopes: scan: %w", err)
		}
		env := &pb.Envelope{
			EventId:     eventID,
			HostId:      hostID,
			ClassId:     pb.OcsfClassId(classUIDOut),
			Payload:     []byte(raw),
			ObservedAt:  timestamppb.New(observedAt),
			CollectedAt: timestamppb.New(collectedAt),
		}
		if err := fn(env); err != nil {
			return err
		}
	}
	return rows.Err()
}
