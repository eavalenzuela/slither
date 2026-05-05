-- +goose Up
-- Phase 6 #113 — Console SSO (OIDC). Two schema changes:
--
--   1. oidc_subject column. Carries the IdP's stable subject claim
--      (the "sub" from the ID token). UNIQUE so the same subject can
--      never bind to two distinct local rows. NULL for password-only
--      users (the bootstrap admin + any operator-mint local accounts);
--      NOT NULL once the row was created via SSO. Subsequent SSO
--      logins match on this column rather than re-deriving the
--      username from the email claim — emails change, subjects don't.
--
--   2. password_hash relaxed to NULL-able. SSO-created users have no
--      local password; allowing NULL keeps INSERT clean instead of
--      forcing a sentinel value the auth path would have to defend
--      against. The login handler already maps "no row" + "wrong
--      password" to the same generic response, and the SSO path
--      never consults password_hash, so a NULL value cannot grant
--      access to a local-login attempt.
--
-- ADR-0011-style additive change: existing rows keep their hash;
-- callers that supply a hash on INSERT continue to work.

ALTER TABLE users
    ADD COLUMN oidc_subject text UNIQUE;

ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

-- Either-or constraint: a row must carry password material OR an
-- OIDC subject (or both, if an operator later binds an OIDC subject
-- to an existing local account — currently unsupported in the UX but
-- the column shape allows it without a future migration).
ALTER TABLE users
    ADD CONSTRAINT users_auth_material_required
        CHECK (password_hash IS NOT NULL OR oidc_subject IS NOT NULL);

-- +goose Down
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_auth_material_required;
ALTER TABLE users
    ALTER COLUMN password_hash SET NOT NULL;
ALTER TABLE users
    DROP COLUMN oidc_subject;
