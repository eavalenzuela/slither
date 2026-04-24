# ADR 0030 — Postgres schema v1 and migration tooling

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

ADR-0012 committed Postgres as the control-plane store but deferred two questions to Phase 2 entry: migration tooling and query layer. Phase 2 §4.1 task #32 is the Phase 2 entry point for the control-plane — it ships the initial schema (six tables) and the harness that applies it. This ADR records both decisions so Phase 5's migration-harness work (§10 deferred question 3) has a documented v1 baseline to evolve from.

## Decision

**Migration tool:** `pressly/goose/v3` with plain-SQL migrations under `server/migrations/`, embedded into the `slither-db` binary via `embed.FS`. No separate CLI tool dependency.

**Query layer:** `pgx/v5` (driver + `pgxpool`) with hand-written SQL in `server/internal/store/pg/`. No ORM, no code generator. Revisit `sqlc` if hand-written SQL becomes unmanageable — typically north of ~30 distinct query shapes.

**Initial schema — six tables:**
- `users` — console operators (username, argon2id hash, role ∈ {viewer, analyst, admin}, disabled_at).
- `hosts` — enrolled agents (host_id UUID, fingerprint fields from `HostFingerprint` proto, enrolled_at, last_seen, cert_serial for revocation, revoked_at, agent_version).
- `enrollment_tokens` — single-use agent-enrollment tokens (sha256 hash only, never plaintext; TTL; used_at + used_by_host on burn).
- `rules` — Sigma rules (stable `uid` from the YAML `id:` field as the wire identity, source YAML, enabled flag, optional compiled bytecode cache).
- `alerts` — lifecycle records (rule_uid as loose reference not FK so rule deletion does not cascade alert history; event_ids array; status enum new/acknowledged/in_progress/closed; reason_code on close; assigned_to).
- `audit_log` — every admin / enrollment / response action (actor_type + actor_id, action string, target_kind + target_id, detail jsonb).

**Conventions:**
- UUIDv4 primary keys via `pgcrypto.gen_random_uuid()`.
- All timestamps are `timestamptz`; DB-side defaults use `now()` so clients don't race.
- Enums are Postgres `CREATE TYPE … AS ENUM (…)` rather than `CHECK (x IN (…))` — invalid values fail at the type level, and enum additions require an explicit migration (forcing review).
- Indexes are declared inline with the tables that need them; no deferred index-creation PRs.
- Every `Up` has a matching `Down` that fully reverses it. Migrations are numbered `NNNNN_short_name.sql` (five-digit prefix leaves room for Phase 3+ additions without renumbering).

## Consequences

- **Easier:** `slither-db migrate` / `slither-db reset` / `slither-db status` subcommands give a single operator surface; CI and docker-compose both call the same binary. The schema is reviewable as plain SQL, which matches the existing reviewer habits around the BPF C sources.
- **Harder:** Hand-written SQL loses compile-time type checking. Mitigation: every query helper in `server/internal/store/pg/` has a unit test exercised by testcontainers-go. Move to `sqlc` if the test surface gets too large to maintain by hand.
- **Follow-up:** Phase 5 (deferred question 3) needs a migration-harness story that covers OCSF version bumps — the v1 schema here is the "before" snapshot it will evolve from. Phase 3 will add a `rules_changed` NOTIFY trigger (#39); skeleton column `rules.updated_at` already accommodates it.

## Alternatives considered

- **`golang-migrate`:** comparable feature set, but its CLI-first ergonomics and external-tool story add a moving part. Goose embeds cleanly into our own binary.
- **`sqlc` from day one:** premature for the six-table Phase 2 shape; the generated code outweighs the hand-written equivalent until the query count grows.
- **Single consolidated `schema.sql`:** kills forward evolution. Goose's numbered-file model is the cost of buying Phase 5's migration path cheaply.
- **Row-level authorization now:** §4 explicitly defers this; the schema carries no `owner_id` / tenant columns. Adding them later is a single ALTER per table.

## References

- PROJECT.md §4.2, §9.1 row 13.
- IMPLEMENTATION.md §4.1 task #32.
- ADR-0012 (control-plane store: Postgres) — this ADR resolves the "migration tooling + ORM" follow-up it flagged.
- Phase 5 deferred question 3 (schema evolution under OCSF version bumps).
