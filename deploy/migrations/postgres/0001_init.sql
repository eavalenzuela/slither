-- Slither control-plane schema bootstrap.
-- Phase 0: create the database and a schema placeholder.
-- Tables (hosts, users, rules, alerts, audit_log, enrollment_tokens) arrive in
-- Phase 2 as a migration harness. This file ensures `slither` db exists and
-- the `slither` role has access.

-- The postgres image already creates DB + user from env vars.
-- We only need to lay out the schema placeholder here.

CREATE SCHEMA IF NOT EXISTS slither AUTHORIZATION slither;

COMMENT ON SCHEMA slither IS 'Slither control-plane objects — Phase 2+';
