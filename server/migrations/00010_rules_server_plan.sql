-- +goose Up
-- ADR-0032 — two-artefact rule shape. Adds the persistence the compiler
-- (Phase 3 #54) writes alongside source_yaml so the control hub can
-- skip server-only rules without recompiling YAML on every Refresh,
-- and so the future server detection engine (#58) reads the plan IR
-- from a stable column rather than re-parsing the rule text.
--
-- Defaults are deliberately stateless-edge so existing rows survive
-- the migration unchanged: every rule rewritten by slither-db
-- insert-rule (or any future console editor) will recompute and
-- overwrite these columns; rows not touched after migration land sit
-- on the safe default until they're next edited.

ALTER TABLE rules
    ADD COLUMN classification text    NOT NULL DEFAULT 'edge_only',
    ADD COLUMN server_plan    jsonb,
    ADD COLUMN force_edge     boolean NOT NULL DEFAULT false;

ALTER TABLE rules
    ADD CONSTRAINT rules_classification_chk
    CHECK (classification IN ('edge_only', 'server_only', 'both'));

-- +goose Down
ALTER TABLE rules DROP CONSTRAINT rules_classification_chk;
ALTER TABLE rules
    DROP COLUMN force_edge,
    DROP COLUMN server_plan,
    DROP COLUMN classification;
