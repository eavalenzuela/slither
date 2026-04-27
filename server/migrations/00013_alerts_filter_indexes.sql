-- +goose Up
-- Phase 3 #62 — indexes covering the filter shapes the /alerts page
-- exposes. Existing alerts_host_status_idx covers (host_id, status,
-- created_at DESC) and alerts_rule_uid_idx covers (rule_uid,
-- created_at DESC); this migration backfills the remaining axes:
--
--   - created_at DESC alone for the unfiltered / time-range list view
--     (the dominant path — operators landing on /alerts without
--     filters paginate by recency).
--   - assigned_to for the analyst's "my open alerts" filter.
--   - severity for severity-only filtering.
--
-- All three are plain B-tree on small int / uuid columns; the storage
-- cost is negligible compared to the alert-stream throughput we expect.

CREATE INDEX alerts_created_at_idx ON alerts (created_at DESC, id DESC);
CREATE INDEX alerts_assigned_to_idx ON alerts (assigned_to, created_at DESC) WHERE assigned_to IS NOT NULL;
CREATE INDEX alerts_severity_idx ON alerts (severity, created_at DESC);

-- +goose Down
DROP INDEX alerts_severity_idx;
DROP INDEX alerts_assigned_to_idx;
DROP INDEX alerts_created_at_idx;
