-- +goose Up
-- ocsf_authentication_3002 stores OCSF class_uid 3002 (authentication)
-- events from the agent's libpam collector: credential checks
-- (pam_authenticate), session opens (pam_open_session) and session
-- closes (pam_close_session) for every PAM client on the host — sshd,
-- sudo, su, login, getty, display managers.
--
-- Hot-path columns are flat so the brute-force and lateral-movement
-- hunts (`WHERE service = 'sshd' AND status_id = 2 GROUP BY src_ip`)
-- never need JSON extraction. user_name is the account PAM was asked
-- about; actor_pid / actor_name are the client process (sshd, sudo).
-- +goose StatementBegin
CREATE TABLE ocsf_authentication_3002 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    event_code      LowCardinality(String),
    service         LowCardinality(String),
    user_name       String,
    src_ip          String,
    src_hostname    String,
    status_id       UInt8,
    status_code     Int32,
    status_detail   LowCardinality(String),
    logon_type_id   UInt8,
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
DROP TABLE ocsf_authentication_3002;
-- +goose StatementEnd
