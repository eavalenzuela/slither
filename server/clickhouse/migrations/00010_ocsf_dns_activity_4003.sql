-- +goose Up
-- ocsf_dns_activity_4003 stores OCSF class_uid 4003 (DNS activity)
-- events from the agent's DNS collector: UDP/53 queries and responses
-- attributed to the asking process. query_name is the hunt column
-- (`WHERE query_name LIKE '%.evil.example'`); answers is the response's
-- rdata joined with commas so `WHERE answers LIKE '%203.0.113.%'` works
-- without JSON.
-- +goose StatementBegin
CREATE TABLE ocsf_dns_activity_4003 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    event_code      LowCardinality(String),
    query_name      String,
    query_type      LowCardinality(String),
    rcode           LowCardinality(String),
    answers         String,
    src_ip          String,
    dst_ip          String,
    dst_port        UInt16,
    actor_pid       UInt32,
    actor_name      LowCardinality(String),

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id)
TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ocsf_dns_activity_4003;
-- +goose StatementEnd
