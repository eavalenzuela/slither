-- +goose Up
-- ocsf_file_system_activity_1001 stores OCSF class_uid 1001 (file lifecycle)
-- events: open, create, modify, delete, rename, etc. Hot-path columns
-- favour path + actor pid lookups (the two queries the events search page
-- and detection drill-downs run most often).
CREATE TABLE ocsf_file_system_activity_1001 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    file_path       String,
    file_name       String,
    file_hash_sha256 String,
    actor_pid       UInt32,
    actor_name      String,

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id);

-- +goose Down
DROP TABLE ocsf_file_system_activity_1001;
