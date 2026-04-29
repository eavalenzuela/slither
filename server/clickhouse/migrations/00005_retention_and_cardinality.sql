-- +goose Up
-- Phase 3 #68: bounded retention + cardinality tuning per ADR-0033.
--
-- TTL: 30 days from observed_at, deleted via background merge. The
-- expression rounds to start-of-day so partitions drop wholesale rather
-- than triggering per-row delete mutations. Operators that want a
-- different retention window (longer for compliance, shorter for cost)
-- override per-table with `ALTER TABLE ... MODIFY TTL ...`.
--
-- LowCardinality: applied to bounded-cardinality string columns
-- (process_name, user_name, actor_name, rule_uid, rule_name) only.
-- The original draft also wrapped severity_id / activity_id, but
-- ClickHouse rejects LowCardinality(UInt8) by default
-- ("allow_suspicious_low_cardinality_types") because the dictionary
-- overhead on a 1-byte integer typically exceeds the saving — the
-- engine is right, those columns stay plain UInt8. Documented in
-- ADR-0033's amendment.
--
-- ALTER TABLE ... MODIFY COLUMN rewrites the affected column on every
-- existing part. In Phase 3 dev / pre-production deployments the cost
-- is small; production deployments running this migration on a hot
-- table should expect a one-off mutation. The Down direction reverts
-- both shape and TTL so a roll-back keeps schema parity with v0.

-- +goose StatementBegin
ALTER TABLE ocsf_process_activity_1007
    MODIFY TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_process_activity_1007
    MODIFY COLUMN process_name LowCardinality(String),
    MODIFY COLUMN user_name    LowCardinality(String);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_file_system_activity_1001
    MODIFY TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_file_system_activity_1001
    MODIFY COLUMN actor_name LowCardinality(String);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_network_activity_4001
    MODIFY TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_network_activity_4001
    MODIFY COLUMN actor_name LowCardinality(String);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_detection_finding_2004
    MODIFY TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_detection_finding_2004
    MODIFY COLUMN rule_uid  LowCardinality(String),
    MODIFY COLUMN rule_name LowCardinality(String);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ocsf_process_activity_1007 REMOVE TTL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_process_activity_1007
    MODIFY COLUMN process_name String,
    MODIFY COLUMN user_name    String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_file_system_activity_1001 REMOVE TTL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_file_system_activity_1001
    MODIFY COLUMN actor_name String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_network_activity_4001 REMOVE TTL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_network_activity_4001
    MODIFY COLUMN actor_name String;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE ocsf_detection_finding_2004 REMOVE TTL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE ocsf_detection_finding_2004
    MODIFY COLUMN rule_uid  String,
    MODIFY COLUMN rule_name String;
-- +goose StatementEnd
