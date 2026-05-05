-- +goose Up
-- Phase 6 #110: hunt_results stores one row per osquery row returned
-- by an extension's live-query response. Aggregated server-side from
-- ClientMessage.HuntResult chunks before insertion.
--
-- columns + values are co-indexed Array(String) — variable-shape
-- result sets are a fact of life for live-query backends. The console's
-- detail page reads (query_id, host_id) ranges; ORDER BY matches.
--
-- 7-day TTL matches IMPLEMENTATION.md §8.1 #110 — hunts are operator-
-- driven point-in-time queries, not durable history. Older results
-- are dropped at part-merge time without operator intervention.
CREATE TABLE hunt_results (
    query_id     UUID,
    host_id      UUID,
    observed_at  DateTime64(3) DEFAULT now64(3),
    columns      Array(String),
    values       Array(String)
)
ENGINE = MergeTree
PARTITION BY toDate(observed_at)
ORDER BY (query_id, host_id, observed_at)
TTL toDate(observed_at) + INTERVAL 7 DAY;

-- +goose Down
DROP TABLE hunt_results;
