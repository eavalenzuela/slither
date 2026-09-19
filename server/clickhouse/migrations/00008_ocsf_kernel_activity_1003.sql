-- +goose Up
-- ocsf_kernel_activity_1003 stores OCSF class_uid 1003 (kernel activity)
-- events from the agent's kernel collector: module load / unload /
-- rejected load, BPF program load, kprobe / uprobe attach.
--
-- The rootkit hunts (`WHERE event_code = 'module_load' AND taints LIKE
-- '%unsigned%'`, `WHERE event_code = 'bpf_prog_load' AND actor_name NOT
-- IN (...)`) read flat columns. actor_cmdline is kept because a rejected
-- load carries no module name — the loader's command line is where the
-- path lives.
-- +goose StatementBegin
CREATE TABLE ocsf_kernel_activity_1003 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    event_code      LowCardinality(String),
    kernel_type     LowCardinality(String),
    kernel_name     String,
    kernel_path     String,
    system_call     LowCardinality(String),
    status_id       UInt8,
    status_code     Int32,
    status_detail   LowCardinality(String),
    taints          String,
    prog_type       LowCardinality(String),
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
DROP TABLE ocsf_kernel_activity_1003;
-- +goose StatementEnd
