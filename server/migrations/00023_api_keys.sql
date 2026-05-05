-- +goose Up
-- Phase 6 #120 — bearer-token API keys for the read-only JSON API.
-- ADR-0040.
--
-- Token shape on the wire: `slither_apikey_<32-byte-url-safe-base64>`.
-- The 16-char prefix index drives lookup so request handlers don't
-- argon2id-verify every row per request — the prefix narrows to (in
-- practice) one row, then the handler verifies that single hash.
-- prefix_idx is a non-unique index because a 16-char base64 prefix
-- (96 bits) is enough to keep the per-prefix candidate count at 1
-- in any realistic deployment, but enforcing UNIQUE would crash
-- mints unnecessarily on the rare collision.
--
-- scopes is jsonb-shape text[] for forward-compatible scope checks
-- (read:events, read:rules, etc.). Phase 6 ships a single implicit
-- "read" scope; the column lands now to avoid a Phase 7 migration.
--
-- created_by FK lets the audit trail tie a key back to the operator
-- who minted it. Cascading delete leaves the keys orphan-revoked
-- when an operator account is removed (preferred over CASCADE-
-- destroy so the audit chain still references a valid id).

CREATE TABLE api_keys (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text        NOT NULL,
    prefix        text        NOT NULL,
    hash          text        NOT NULL, -- argon2id-encoded
    created_by    uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    scopes        text[]      NOT NULL DEFAULT ARRAY['read']::text[]
);

CREATE INDEX api_keys_prefix_idx ON api_keys (prefix);

-- Console list page renders newest-first.
CREATE INDEX api_keys_created_idx ON api_keys (created_at DESC);

-- +goose Down
DROP TABLE api_keys;
