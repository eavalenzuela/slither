-- +goose Up
-- ocsf_process_activity_1007 stores OCSF class_uid 1007 (process lifecycle)
-- events. Shared columns first, then class-specific materialised columns
-- pulled out for search hot-paths (host inventory + process tree views).
-- The full canonical OCSF JSON lives in `raw` so the schema can evolve
-- without rewriting historical rows.
CREATE TABLE ocsf_process_activity_1007 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    -- Class-specific hot-path columns.
    activity_id     UInt8,
    pid             UInt32,
    parent_pid      UInt32,
    process_name    String,
    exec_path       String,
    cmdline         String,
    user_name       String,
    exit_code       Nullable(Int32),

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id);

-- +goose Down
DROP TABLE ocsf_process_activity_1007;
