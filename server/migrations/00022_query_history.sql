-- +goose Up
-- Phase 6 #116(a) — events query history. Last 50 queries per user
-- so the operator can re-run a recent search without retyping. The
-- in-flight constraint is intentionally NOT enforced via window /
-- triggers; the writer trims excess rows on every insert (cheap, runs
-- under the user's own session lifetime).
--
-- Stored shape: full URL query string (everything after `?` on
-- /events?...). The parsing layer round-trips this back into the
-- /events filter handler, so any future filter additions land
-- transparently.

CREATE TABLE query_history (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    surface     text        NOT NULL CHECK (surface IN ('events', 'alerts', 'hunts')),
    raw         text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX query_history_user_created_idx
    ON query_history (user_id, created_at DESC);

-- +goose Down
DROP TABLE query_history;
