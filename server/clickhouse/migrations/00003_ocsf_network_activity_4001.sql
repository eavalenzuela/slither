-- +goose Up
-- ocsf_network_activity_4001 stores OCSF class_uid 4001 (network lifecycle)
-- events: TCP connects, listens, etc. Endpoint columns are flat for query
-- ergonomics — `WHERE dst_ip = ...` should not require JSON extraction.
CREATE TABLE ocsf_network_activity_4001 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    protocol        LowCardinality(String),
    src_ip          String,
    src_port        UInt16,
    dst_ip          String,
    dst_port        UInt16,
    actor_pid       UInt32,
    actor_name      String,

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id);

-- +goose Down
DROP TABLE ocsf_network_activity_4001;
