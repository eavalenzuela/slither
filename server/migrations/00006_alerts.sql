-- +goose Up
-- Alert lifecycle per PROJECT.md §5. rule_uid is intentionally NOT a FK
-- to rules(uid): deleting a rule must not cascade away alert history. The
-- console joins on rule_uid opportunistically to show rule names, and
-- falls back to the stored value if the rule is gone.
CREATE TYPE alert_status AS ENUM ('new', 'acknowledged', 'in_progress', 'closed');

CREATE TABLE alerts (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_uid      text         NOT NULL,
    host_id       uuid         NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    event_ids     uuid[]       NOT NULL DEFAULT '{}', -- OCSF event_ids that triggered
    severity      smallint     NOT NULL, -- OCSF severity_id 1..6
    status        alert_status NOT NULL DEFAULT 'new',
    reason_code   text,
    assigned_to   uuid         REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    closed_at     timestamptz,
    CHECK (severity BETWEEN 1 AND 6),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);

-- Primary operator view is "new+ack+in-progress per host, newest first".
CREATE INDEX alerts_host_status_idx ON alerts (host_id, status, created_at DESC);
-- Rule-centric view for the rule detail page.
CREATE INDEX alerts_rule_uid_idx ON alerts (rule_uid, created_at DESC);

-- +goose Down
DROP TABLE alerts;
DROP TYPE alert_status;
