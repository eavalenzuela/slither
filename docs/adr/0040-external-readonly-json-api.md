# ADR-0040: External read-only JSON API for BAS integrations

**Status:** accepted

**Date:** 2026-05-03

## Context

Slither's read surface today is HTML+HTMX only at `/events`, `/alerts`,
`/hosts`, `/iocs`, `/hunt`. Every authenticated route gates on the
console's argon2id-password + `scs/pgxstore` session cookie. There is
no machine-readable JSON variant, no bearer-token auth, no API-key
store. `/healthz` exists at `console.go:140` but returns a plain-text
"ok" body.

External consumers — concretely **eyeexam**, the in-house BAS scoring
harness at `../eyeexam` — need to programmatically query Slither's
event store after firing a simulated attack to score whether the
expected detection fired. eyeexam runs unattended (under systemd, in
CI), cannot do an interactive `/login` flow, and explicitly should not
share operator session cookies. Today it ships a stub client at
`internal/detector/slither.go` that targets a fictional API; it is
non-functional against any real Slither deployment.

The full contract is documented in `../eyeexam/docs/slither-api-requirements.md`.
Summarised: JSON `POST /api/v1/events/search` with bearer-token auth,
filterable by `host_id`/`host_name`, `sigma_id`/`rule_uid`, `tag`
(ATT&CK technique ID), `class_uids`, `since`/`until`, with cursor
pagination matching the existing HTML pagination. Plus a JSON
`/api/v1/healthz` and an optional `/api/v1/rules` discovery endpoint.
No write paths, no streaming, no HTML.

This was not in ADR-0037's Phase 6 scope. The right call is to absorb
it inside Phase 6 — eyeexam's value (closing the BAS-detection-scoring
loop on a real Slither deployment) is reachable inside the current
phase's effort budget, and pushing to Phase 7 leaves eyeexam with a
permanently non-functional detector through all of Phase 6.

## Decision

### Add a JSON API tree at `/api/v1/*`

Separate route subtree from the HTML console. Same `chi.Router` mux,
but every `/api/v1/*` route lives behind a bearer-token middleware
that has zero coupling to the console's session cookie. The console
and the API share the underlying ClickHouse store, the existing pg
control plane, and the existing `ch.Store.SearchEvents` query path —
they do not share auth or output-format machinery.

Two scope rails:

1. **Read-only.** No event ingest, no rule push, no agent command
   dispatch, no enrolment-token mint, no response-action trigger
   over the API tree. eyeexam never writes; locking the surface
   read-only kept-tight prevents the API from drifting into a
   parallel control plane. Future write surfaces (if any) need a
   new ADR + an explicit scope expansion.
2. **Stable contract.** `/api/v1/...` is the public-facing version;
   field renames or removals require `/api/v2/...` with dual-target
   migration window. Additive field changes are permitted under the
   v1 prefix.

### Auth: per-deployment bearer tokens, hashed at rest

| Surface | Decision |
|---------|----------|
| Token format | 32 random bytes, URL-safe base64, prefixed `slither_apikey_` so they're greppable in logs and recognisable in `Authorization` headers |
| Storage | New pg `api_keys` table: `id` UUID, `name` text, `hash` text (argon2id of the raw token, same params as `users.password_hash`), `created_by` UUID FK to users, `created_at`, `last_used_at` (nullable), `revoked_at` (nullable), `scopes` text[] |
| Mint flow | Admin-only console page `/api/keys` — POST mints a fresh token, displays once via `scs` flash (one-shot), persists hash. Plaintext is never stored. Mirrors enrolment-token UX (#45) |
| Revoke flow | Admin-only POST `/api/keys/{id}/revoke` flips `revoked_at = now()`. Audited (`api_key.revoked` reason code) |
| Verification | Middleware: parse `Authorization: Bearer <token>` header, lookup via prefix index (the first 16 chars of the token are a non-secret lookup key on top of the argon2id verify, so we don't argon2id every row in the table). 401 on missing/malformed/revoked, 403 on out-of-scope |
| Scopes | `events:read`, `rules:read`. v1 only mints both together; the column exists so future API surfaces can issue narrower keys |
| Rate limiting | Out of scope for v1. Operators run eyeexam in a controlled environment; per-token rate-limit lands when an external integration shows a need |
| Token rotation | Mint a new token, revoke the old. No automatic rotation; eyeexam is the only consumer and it survives a manual swap |

The argon2id verify pattern is **not** "argon2id every key on every
request" — that's O(N) per request. Instead the token's first 16 bytes
of base64 (12 bytes of entropy, ~2^96 keyspace — collision-free for any
realistic key population) function as a lookup index; argon2id verify
only runs on the matching row. This matches how the password login
flow already works (`pg.GetUserByUsername` then argon2id) but with the
key-prefix in place of the username.

OIDC (Phase 6 #113) is the **human** auth backend. Bearer tokens are
the **machine** auth backend. They sit alongside each other; neither
replaces the other.

### Required endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /api/v1/healthz` | none | JSON `{"ok": true}` for eyeexam's `Detector.HealthCheck`. Distinct from the existing `/healthz` (HTML console) so the API consumer never sees an HTML body |
| `POST /api/v1/events/search` | `Bearer` (scope: `events:read`) | JSON event search per eyeexam contract. Wraps `ch.Store.SearchEvents` |
| `GET /api/v1/rules` | `Bearer` (scope: `rules:read`) | Optional. Lists currently-loaded Sigma rules with optional `?since=&technique=` filters. eyeexam degrades gracefully without it |

### Filter additions on `EventFilter` + `SearchEvents`

`server/internal/store/ch/search.go`:

| New field | Type | WHERE clause |
|-----------|------|--------------|
| `RuleUID` | `string` | `rule_uid = ?` (LowCardinality column already on `ocsf_detection_finding_2004`) |
| `Tag` | `string` | `has(mitre_techniques, ?)` (Array(String) column already on `ocsf_detection_finding_2004`) |

Both are `class_uids ⊆ {2004}` — they only narrow on detection-finding
rows. Querying with `Tag != ""` and `class_uids` not including 2004
returns no rows by construction, which is correct.

The HTML console's `/events` page does **not** grow these filters in
this task — keeping the JSON API additive and not touching the HTML
form means we don't accidentally regress anyone's saved-query UX from
#115.

### MITRE tag plumbing — agent → OCSF → ClickHouse

Today `pkg/ruleast.Rule.Tags []string` carries Sigma's `tags:` block
verbatim, but `agent/internal/ruleengine/finding.go.buildFinding` does
not propagate them onto the OCSF `DetectionFinding`. The CH
`mitre_techniques` column on `ocsf_detection_finding_2004` was
provisioned in migration 00004 and has been unpopulated since.

This task plumbs them:

1. **`buildFinding`** picks up `rule.Tags`, normalises each to
   lowercase + strips non-`attack.t*`/`attack.s*`/`attack.g*` prefixed
   entries (eyeexam contract: ATT&CK technique IDs only), and
   populates `ocsf.DetectionFinding.MitreATTACK[]` with `MitreTag{
   Technique: { UID: "T1070.003" } }` shape.
2. **CH writer (`server/internal/store/ch/writer.go`)** extracts the
   Technique UIDs into `mitre_techniques` Array(String) on insert.
3. **Backfill is not in scope** — pre-existing detection findings stay
   tag-less. eyeexam's queries are post-test, querying its own freshly-
   fired detections, so historical tag-coverage is irrelevant.

### Versioning + breaking-change discipline

| Change shape | Treatment |
|--------------|-----------|
| Adding a request filter field | Additive, ignored by older clients |
| Adding a response field | Additive, ignored by older clients |
| Renaming a field | `/api/v2/` with dual-target window |
| Removing a field | `/api/v2/` with dual-target window |
| Tightening request validation (e.g. making an optional field required) | `/api/v2/` |

Mirrors ADR-0011's wire-stability invariant on `slither.v1` but for
the HTTP API surface.

### Rate limiting + abuse protection: deferred

eyeexam is the only known consumer; its query pattern is bounded by
the cadence of BAS test execution (once per Atomic-test run,
typically minutes apart). Adding rate-limiting infrastructure now
designs against a synthetic threat. Reopen criterion: a second
external consumer shows up, or eyeexam moves into a continuous-
backtest mode that polls aggressively.

If/when needed, the natural shape is a leaky-bucket limiter keyed on
api_key_id, with a per-key configurable budget — slots into the
existing middleware chain.

## Consequences

- **eyeexam becomes functional against real Slither deployments.**
  After this task lands, eyeexam's `internal/detector/slither.go` rewrite
  is a ~1-file change on their side.
- **Phase 6 grows by one numbered task.** §8.1 already has a
  17-task shape; this is task #18 (renumbered as #120, exit becomes
  #121). Effort estimate stays inside the 8–10 week Phase 6 envelope.
- **`mitre_techniques` becomes load-bearing.** The CH column has been
  unused since migration 00004 — once the agent populates it via the
  finding-builder change, it's part of the contract. Schema-evolution
  rules (Phase 5 #99 harness) apply to changes from here forward.
- **API auth is genuinely orthogonal to console auth.** Argon2id+SCS
  is for humans, OIDC (#113) is for SSO humans, bearer tokens are for
  machines. None of the three implies the others.
- **No write API surface.** Future BAS integrations or other
  programmatic consumers needing to push state into Slither (rule
  uploads from `slither-rulekit`, etc.) need a new ADR — read and
  write surfaces have different blast radii and auth needs.
- **Tag plumbing closes a long-standing gap.** The `mitre_techniques`
  column was forward-looking infrastructure waiting for a consumer;
  this task is the consumer. Operators querying via the console will
  also benefit indirectly when #115 saved queries lands, even though
  the HTML filter form doesn't grow tag inputs in this task.

## References

- ADR-0011 (transport gRPC mTLS — wire-stability invariant precedent)
- ADR-0037 (Phase 6 scope — this ADR amends §8 task list to add #120)
- `../eyeexam/docs/slither-api-requirements.md` (the contract this ADR
  implements)
- `server/internal/store/ch/search.go` (existing `EventFilter`,
  `SearchEvents`, `Cursor`)
- `server/internal/console/events.go` (existing HTML handler — model
  for the new JSON handler)
- `agent/internal/ruleengine/finding.go` (where `rule.Tags` is dropped
  today — the agent-side plumbing change)
- `pkg/ocsf/finding.go` (`DetectionFinding.MitreATTACK` struct already
  defined, ready to populate)
- `server/clickhouse/migrations/00004_ocsf_detection_finding_2004.sql`
  (`mitre_techniques Array(String)` column already provisioned)
