-- +goose Up
-- Phase 6 #115 — saved queries. The console captures URL query
-- params from a filter form on /events, /alerts, or /hunt and stores
-- them as a JSON map keyed by the surface that knows how to consume
-- them. v1 keeps the stored shape opaque to pg; the rendering surface
-- is responsible for round-trip parsing.
--
-- ADR-0037 keeps shared queries out of v1 — every saved query is
-- per-user. Deleting the user cascades the saved rows; per-row
-- deletion happens via the operator's /queries page.
--
-- params is jsonb so a future schema change (e.g. adding a query
-- string after #116 ships /events query language) lands as an
-- additive jsonb field without an ALTER.

CREATE TABLE saved_queries (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        text        NOT NULL,
    surface     text        NOT NULL CHECK (surface IN ('events', 'alerts', 'hunts')),
    params      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Per-user list page renders this newest-first.
CREATE INDEX saved_queries_user_idx
    ON saved_queries (user_id, created_at DESC);

-- Operator can't have two queries with the same (surface, name).
-- Cross-surface duplicates are allowed (one "today" for events, a
-- different "today" for alerts) since the surface disambiguates the
-- click target.
CREATE UNIQUE INDEX saved_queries_user_surface_name_idx
    ON saved_queries (user_id, surface, name);

-- +goose Down
DROP TABLE saved_queries;
