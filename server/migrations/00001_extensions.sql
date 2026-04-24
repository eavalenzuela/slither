-- +goose Up
-- pgcrypto supplies gen_random_uuid(), used as the default for every UUID PK.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- +goose Down
DROP EXTENSION IF EXISTS pgcrypto;
