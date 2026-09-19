-- +goose Up
-- ocsf_container_lifecycle_6000 stores OCSF class_uid 6000 (container
-- lifecycle) events from the agent's cgroup collector: container create
-- (cgroup made), start (first exec inside it), stop (cgroup removed).
-- The container id and runtime are parsed from the cgroup path; names
-- and images are not visible from the kernel.
-- +goose StatementBegin
CREATE TABLE ocsf_container_lifecycle_6000 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    event_code      LowCardinality(String),
    container_id    String,
    runtime         LowCardinality(String),
    cgroup_path     String,
    actor_pid       UInt32,
    actor_name      LowCardinality(String),
    actor_cmdline   String,

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id)
TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ocsf_container_lifecycle_6000;
-- +goose StatementEnd
