-- +goose Up
CREATE TYPE user_role AS ENUM ('viewer', 'analyst', 'admin');

CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text        NOT NULL UNIQUE,
    password_hash text        NOT NULL, -- argon2id, encoded form ($argon2id$...)
    role          user_role   NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    disabled_at   timestamptz
);

-- +goose Down
DROP TABLE users;
DROP TYPE user_role;
