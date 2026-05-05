-- +goose Up
-- Phase 6 #115 — per-user dashboards. A dashboard is a user-owned
-- collection of cards; each card references one saved_queries row by
-- id. layout carries the rendering hints (card order, optional
-- per-card label override). v1 keeps layout simple — no resize, no
-- drag — so layout stays jsonb to leave room for Phase 7+
-- enrichments without an ALTER.
--
-- ADR-0037 holds shared dashboards for Phase 7+; every dashboard is
-- per-user. The user FK cascades on delete to clean up an
-- offboarded user's dashboards in one shot.
--
-- Card → saved_query references aren't pg-level FKs because the spec
-- requires "deleting a saved-query that's referenced by a dashboard
-- card → card surfaces a (query deleted) placeholder instead of
-- erroring". A FK with ON DELETE CASCADE would silently drop the
-- card; a FK with ON DELETE RESTRICT would block the saved-query
-- deletion. Layout-jsonb lookup keeps the dangling-id semantics the
-- rendering code wants.

CREATE TABLE dashboards (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        text        NOT NULL,
    layout      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX dashboards_user_idx
    ON dashboards (user_id, created_at DESC);

CREATE UNIQUE INDEX dashboards_user_name_idx
    ON dashboards (user_id, name);

-- +goose Down
DROP TABLE dashboards;
