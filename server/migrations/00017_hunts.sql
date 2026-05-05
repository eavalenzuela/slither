-- +goose Up
-- Phase 6 #110: live-query hunts. The dispatching operator picks a
-- backend (osquery in v1), an optional host filter (substring match
-- on hostname or hosts.id; empty == every connected host), a per-host
-- row cap and a soft timeout. Each hunt row aggregates the response
-- envelope; the row chunks themselves land in ClickHouse
-- (hunt_results) on a 7-day TTL — we do not pay pg storage for every
-- row.
--
-- target_host_count + completed_host_count are tracked here rather
-- than derived from CH so the console's status column is a cheap
-- single-row read regardless of result-set size.

CREATE TABLE hunts (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    dispatched_by         uuid        NOT NULL REFERENCES users (id) ON DELETE SET NULL,
    backend               text        NOT NULL DEFAULT 'osquery' CHECK (backend IN ('osquery')),
    query                 text        NOT NULL,
    host_filter           text        NOT NULL DEFAULT '',
    timeout_secs          integer     NOT NULL DEFAULT 60 CHECK (timeout_secs > 0 AND timeout_secs <= 3600),
    max_rows_per_host     integer     NOT NULL DEFAULT 10000 CHECK (max_rows_per_host >= 0),
    status                text        NOT NULL DEFAULT 'dispatching' CHECK (status IN (
                              'dispatching',
                              'running',
                              'completed',
                              'timed_out',
                              'cancelled'
                          )),
    target_host_count     integer     NOT NULL DEFAULT 0,
    completed_host_count  integer     NOT NULL DEFAULT 0,
    error                 text,
    dispatched_at         timestamptz NOT NULL DEFAULT now(),
    completed_at          timestamptz
);

-- List page is "newest hunts first by status"; this index covers it.
CREATE INDEX hunts_status_dispatched_at_idx
    ON hunts (status, dispatched_at DESC);

-- "All hunts I dispatched" lookup for the operator's profile page (a
-- future feature; cheap to add now).
CREATE INDEX hunts_dispatched_by_idx
    ON hunts (dispatched_by, dispatched_at DESC);

-- +goose Down
DROP TABLE hunts;
