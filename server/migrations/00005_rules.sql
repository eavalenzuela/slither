-- +goose Up
-- Sigma rule records. `uid` is the Sigma `id:` field from the YAML and is
-- the wire identity carried in RuleSet messages + DetectionFinding.rule.uid
-- — it's stable across renames and rule-source edits, so we key on it
-- rather than the DB-assigned row id.
--
-- `compiled` caches the ruleast bytecode so #39 doesn't recompile on every
-- Session open; nullable so a freshly-inserted rule is still usable before
-- the server's compile-and-cache pass runs.
CREATE TABLE rules (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    uid          text        NOT NULL UNIQUE,
    name         text        NOT NULL,
    source_yaml  text        NOT NULL,
    compiled     bytea,
    enabled      boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   uuid        REFERENCES users (id) ON DELETE SET NULL
);

-- +goose Down
DROP TABLE rules;
