-- +goose Up
-- Hosts are the agent-enrollment record. Fingerprint fields mirror the
-- slither.v1.HostFingerprint proto so the enrollment RPC (#34) persists
-- exactly what it received. last_seen is updated on every heartbeat;
-- stale/offline transitions are derived at read time from its age
-- against the heartbeat cadence + missed-count policy (§2.4).
CREATE TABLE hosts (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        text        NOT NULL,
    machine_id      text        NOT NULL,
    os_name         text        NOT NULL,
    os_version      text        NOT NULL,
    kernel_version  text        NOT NULL,
    arch            text        NOT NULL,
    agent_version   text,
    cert_serial     text        NOT NULL,
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz,
    revoked_at      timestamptz
);

-- cert_serial is the lookup key when validating an inbound mTLS cert
-- against the revocation list (#44).
CREATE UNIQUE INDEX hosts_cert_serial_idx ON hosts (cert_serial);

-- +goose Down
DROP TABLE hosts;
