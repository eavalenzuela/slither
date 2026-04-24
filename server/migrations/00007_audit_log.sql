-- +goose Up
-- audit_log captures every action with security meaning: console login,
-- enrollment attempts (success and rejection), rule edits, alert state
-- changes, response actions (Phase 4). actor_id and target_id are text,
-- not FKs, because the referenced rows may be deleted while the log row
-- must survive.
CREATE TYPE actor_type AS ENUM ('user', 'system', 'agent');

CREATE TABLE audit_log (
    id           bigserial    PRIMARY KEY,
    actor_type   actor_type   NOT NULL,
    actor_id     text,
    action       text         NOT NULL,
    target_kind  text,
    target_id    text,
    detail       jsonb        NOT NULL DEFAULT '{}',
    created_at   timestamptz  NOT NULL DEFAULT now()
);

-- Most reads are "recent N entries, newest first", optionally filtered by
-- actor or action. Composite on created_at desc keeps the common case fast.
CREATE INDEX audit_log_created_at_idx ON audit_log (created_at DESC);
CREATE INDEX audit_log_action_idx     ON audit_log (action, created_at DESC);

-- +goose Down
DROP TABLE audit_log;
DROP TYPE actor_type;
