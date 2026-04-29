-- +goose Up
-- Phase 4 #72: durable on-host record of every response action (operator-
-- driven from the console OR edge auto-respond). Audit + state-machine
-- row in one. Reversal is a NEW row with parent_action pointing at the
-- original; the parent flips to `reverted` only when the reverse
-- action's status is `done` (forensic chain stays append-only). See
-- ADR-0034 for the auth model + schema rationale.
--
-- The CHECK on (operator_id IS NOT NULL OR rule_uid IS NOT NULL) is the
-- "who asked?" invariant — every row is either operator-driven or
-- rule-driven, never neither.

CREATE TABLE response_actions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        uuid        REFERENCES alerts (id) ON DELETE SET NULL,
    host_id         uuid        NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    action          text        NOT NULL CHECK (action IN (
                        'kill_process',
                        'kill_tree',
                        'quarantine_file',
                        'isolate_host',
                        'unisolate_host',
                        'collect_artifacts'
                    )),
    target          text        NOT NULL,
    operator_id     uuid        REFERENCES users (id) ON DELETE SET NULL,
    rule_uid        text,
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending',
                        'running',
                        'done',
                        'failed',
                        'denied_by_policy',
                        'reverted'
                    )),
    reason_code     text,
    result_blob     bytea,
    parent_action   uuid        REFERENCES response_actions (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    completed_at    timestamptz,
    CHECK (operator_id IS NOT NULL OR rule_uid IS NOT NULL)
);

-- Operator history per host: "show me everything we did to host X."
CREATE INDEX response_actions_host_created_idx
    ON response_actions (host_id, created_at DESC);

-- Reverse-chain lookup: "did anyone revert action Y?"
CREATE INDEX response_actions_parent_idx
    ON response_actions (parent_action) WHERE parent_action IS NOT NULL;

-- Pending-queue lookup for the dispatcher: small in normal operation
-- (most pending rows transition fast), but a partial index keeps the
-- scan O(pending) rather than O(history).
CREATE INDEX response_actions_pending_idx
    ON response_actions (host_id, created_at) WHERE status = 'pending';

-- +goose Down
DROP TABLE response_actions;
