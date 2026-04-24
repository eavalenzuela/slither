-- +goose Up
-- Single-use agent-enrollment tokens. We store sha256(token), never the
-- plaintext — the UI shows the token exactly once at creation time (#45).
-- Burn is an atomic UPDATE … WHERE used_at IS NULL done inside the same
-- transaction that inserts the hosts row in the Enroll RPC (#34).
CREATE TABLE enrollment_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      bytea       NOT NULL,
    hostname_hint   text,
    created_by      uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    used_by_host    uuid        REFERENCES hosts (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX enrollment_tokens_hash_idx ON enrollment_tokens (token_hash);

-- +goose Down
DROP TABLE enrollment_tokens;
