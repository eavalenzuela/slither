-- +goose Up
-- ocsf_detection_finding_2004 stores OCSF class_uid 2004 (detection
-- finding) events emitted by the rule engine. Triggering event ids are
-- carried as Array(UUID) so the alerts page can pivot to the underlying
-- events without re-parsing JSON. mitre_techniques is a flat array of
-- T-codes for fast tactic/technique faceting.
CREATE TABLE ocsf_detection_finding_2004 (
    event_id        UUID,
    host_id         UUID,
    observed_at     DateTime64(9),
    collected_at    DateTime64(9),
    class_uid       UInt32,
    severity_id     UInt8,

    activity_id     UInt8,
    rule_uid        String,
    rule_name       String,
    finding_uid     String,
    finding_status  LowCardinality(String),
    triggering_event_ids Array(UUID),
    mitre_techniques     Array(String),

    raw             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id);

-- +goose Down
DROP TABLE ocsf_detection_finding_2004;
