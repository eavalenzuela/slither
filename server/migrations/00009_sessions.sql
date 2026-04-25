-- +goose Up
-- Session storage for the operator console (Phase 2 §4.1 task #41).
-- Schema is the standard alexedwards/scs/pgxstore layout — kept here
-- so migration ordering is deterministic alongside the rest of the
-- control plane (an ad-hoc CREATE inside the scs library would race
-- with `slither-db migrate` on a fresh stack).
CREATE TABLE sessions (
    token  text        PRIMARY KEY,
    data   bytea       NOT NULL,
    expiry timestamptz NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- +goose Down
DROP TABLE sessions;
