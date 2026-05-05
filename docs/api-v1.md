# Slither JSON API v1

**Status:** stable, contract-frozen at v1 per ADR-0040.

The Slither server exposes a small read-only JSON API under
`/api/v1/`, served on the same listener as the HTML console.
Designed for BAS scoring (eyeexam) and other external integrations
that need structured access to detection findings.

## Authentication

Every endpoint except `/api/v1/healthz` requires a bearer token:

```
Authorization: Bearer slither_apikey_<32-byte-base64>
```

Tokens are minted by an admin operator at
`https://<console>/api/keys`. The plaintext is shown exactly once at
mint; the consumer's secret store is responsible for the long-term
copy. Revocation is one click from the same page.

Failure responses are JSON, never HTML:

```json
{"error": "invalid_token", "message": "token rejected"}
```

## Endpoints

### `GET /api/v1/healthz`

Unauthenticated liveness probe.

```json
{"ok": true}
```

Returns 200 when the API process is reachable. The probe is **shallow**
— Postgres + ClickHouse health is not checked here. Operators wanting
deep healthchecks use the HTML console's `/healthz`.

### `POST /api/v1/events/search`

Search detection findings + raw events. Body:

```json
{
  "host_id":      "uuid-string-optional",
  "host_name":    "alternate-to-host_id-optional",
  "rule_uid":     "sigma-id-optional",
  "sigma_id":     "alias-of-rule_uid-optional",
  "tag":          "T1070.003-optional",
  "class_uids":   [2004, 1007],
  "severity_id":  3,
  "since":        "2026-05-01T00:00:00Z",
  "until":        "2026-05-02T00:00:00Z",
  "cursor":       "opaque-string-from-prior-page",
  "limit":        50
}
```

All fields optional. `host_name` resolves to `host_id` server-side via
a Postgres lookup; an unknown name returns an empty `hits` array
rather than a 404. `tag` matches the OCSF `mitre_techniques`
ClickHouse array (populated from each finding's MITRE ATT&CK tags via
the agent's buildFinding) — both top-level techniques (`T1059`) and
sub-techniques (`T1070.003`) are accepted. `cursor` opaquely encodes
the (observed_at, event_id) pair the previous page ended on.

GET form is also accepted for `curl` / dev convenience:

```
GET /api/v1/events/search?tag=T1070.003&since=2026-05-01T00:00:00Z
```

Response:

```json
{
  "hits": [
    {
      "id":          "uuid",
      "host_id":     "uuid",
      "host_name":   "web-01",
      "class_uid":   2004,
      "severity_id": 4,
      "observed_at": "2026-05-01T12:34:56.789Z",
      "rule_uid":    "8b7c4d00-0001-4000-8000-000000000001",
      "rule_name":   "Bash reverse shell via /dev/tcp",
      "raw":         { ... full OCSF event ... }
    }
  ],
  "next_cursor": "opaque"
}
```

`next_cursor` is empty when the result set ended on this page. `raw`
is the canonical OCSF JSON for the row — class-specific and
forward-compatible with future schema additions.

### `GET /api/v1/rules`

List currently-enabled Sigma rules. Optional filters:

```
GET /api/v1/rules?since=2026-05-01T00:00:00Z&technique=T1070
```

`since` returns rules whose `updated_at >= cutoff`. `technique`
substring-matches against the lowercased Sigma source so
`?technique=t1070` matches both `attack.t1070` and `attack.t1070.003`
without re-parsing YAML.

Response:

```json
{
  "rules": [
    {
      "uid":            "8b7c4d00-...",
      "name":           "Bash reverse shell via /dev/tcp",
      "classification": "edge_only",
      "updated_at":     "2026-05-01T12:00:00Z"
    }
  ]
}
```

## Error codes

| Status | `error`              | When                                                |
|--------|----------------------|-----------------------------------------------------|
| 400    | `bad_request`        | Malformed JSON / unknown query field                |
| 400    | `bad_since`          | `since` not RFC3339                                 |
| 400    | `bad_until`          | `until` not RFC3339                                 |
| 400    | `bad_cursor`         | Cursor format unrecognised                          |
| 401    | `invalid_token`      | Missing / malformed / unknown / revoked bearer      |
| 500    | `internal_error`     | Postgres / ClickHouse blip                          |
| 503    | `ch_unavailable`     | ClickHouse store not wired                          |
| 503    | `pg_unavailable`     | Postgres store not wired                            |

## Versioning

The v1 contract is frozen — additive fields land here; breaking
changes go to `/api/v2/`. ADR-0040 records the freeze.

## Audit trail

Every JSON-API request lands an `api_key.used` audit row keyed off
the resolved key id. Mints + revokes log `api_key.minted` /
`api_key.revoked` from the console pages.
