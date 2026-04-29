# ADR-0033: ClickHouse retention + cardinality tuning v1

**Status:** accepted

**Date:** 2026-04-29

## Context

Phase 2 §10.4 deferred CH retention to "tune at Phase 3 once real
event volumes are observable". Phase 3 §5.1 #68 closes that out.

Two pressures:

1. **Storage growth.** Phase 1 load tests measured ~12k events/s on
   Debian 13 (~36k/s on the spec'd target host). At 36k/s × 86400 s/d
   × 4 OCSF tables × ~150 B/row in the column projection (excluding
   `raw`) we're looking at ~2 TB/day of just hot-path columns. With
   `raw` the multiplier doubles. A retention bound is mandatory; the
   only question is the default and how operators tune it.

2. **Query speed at the small-end.** Phase 2 ships UInt8 / String
   columns for fields whose live cardinality is one of:
   - severity_id ∈ 1..6,
   - activity_id ∈ a small per-class enum (1..2 for process, 1..6 for
     file, etc.),
   - rule_uid / rule_name / process_name / user_name / actor_name —
     bounded by the number of rules / processes / accounts on a host
     fleet, almost always < 10k distinct values per partition.

   ClickHouse's `LowCardinality(...)` modifier converts these to a
   per-part dictionary; for cardinalities under ~50k it's a 5-10×
   compression win and faster GROUP BY / WHERE in the bargain. We
   left it out of the v1 schema (ADR-0031) on the "tune at Phase 3"
   line — same line we're crossing now.

## Decision

### Retention: 30-day TTL on every ocsf_* table

Migration `00005_retention_and_cardinality.sql` adds:

```sql
ALTER TABLE ocsf_<class>_<uid>
  MODIFY TTL toStartOfDay(observed_at) + INTERVAL 30 DAY DELETE;
```

`toStartOfDay(observed_at)` rounds the TTL bucket to a whole day, so
ClickHouse's background merge drops whole partitions wholesale rather
than triggering per-row delete mutations. With `PARTITION BY
toYYYYMMDD(observed_at)` (ADR-0031) every partition is exactly one
day, so partition drop and TTL drop align.

**Why 30 days as the default:**
- Long enough for typical incident-response review windows (most
  detections trigger within a week; a fortnight of forensic context
  is plenty).
- Short enough that a small-fleet (50-host) deployment fits in single
  digits of TB.
- Operators with compliance reasons to keep longer (HIPAA = 6 years,
  PCI = 1 year for some artefacts) override per-table:

```sql
ALTER TABLE ocsf_detection_finding_2004
  MODIFY TTL toStartOfDay(observed_at) + INTERVAL 365 DAY DELETE;
```

Per-table override beats one global knob because retention pressures
genuinely differ per class. Process activity rolls off fast; detection
findings are the row you want to keep.

**Why TTL on `observed_at`, not `collected_at`:**
- `observed_at` is when the event happened on the host. Operators
  reasoning about "events from yesterday" mean yesterday-host-time,
  not yesterday-the-server-saw-it.
- `collected_at` advances even for backfilled events (an offline
  agent reconnecting and replaying its buffer); TTL on `collected_at`
  would let truly-old events live forever if the agent was offline
  long enough.

**Why DELETE, not RECOMPRESS:**
- ClickHouse supports `TTL ... TO DISK '<name>' / RECOMPRESS CODEC ...`
  to tier data to cheaper storage instead of dropping it. That's the
  obvious Phase 5 lever once we have multi-tier deployments. v1 keeps
  the migration single-action; tiering arrives with the storage-
  hierarchy ADR if it lands at all.

### Cardinality: LowCardinality on bounded-cardinality columns

The same migration MODIFY-COLUMNs:

| Table                              | Column         | Old type   | New type                    |
|------------------------------------|----------------|------------|-----------------------------|
| ocsf_process_activity_1007         | severity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_process_activity_1007         | activity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_process_activity_1007         | process_name   | String     | LowCardinality(String)      |
| ocsf_process_activity_1007         | user_name      | String     | LowCardinality(String)      |
| ocsf_file_system_activity_1001     | severity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_file_system_activity_1001     | activity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_file_system_activity_1001     | actor_name     | String     | LowCardinality(String)      |
| ocsf_network_activity_4001         | severity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_network_activity_4001         | activity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_network_activity_4001         | actor_name     | String     | LowCardinality(String)      |
| ocsf_detection_finding_2004        | severity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_detection_finding_2004        | activity_id    | UInt8      | LowCardinality(UInt8)       |
| ocsf_detection_finding_2004        | rule_uid       | String     | LowCardinality(String)      |
| ocsf_detection_finding_2004        | rule_name      | String     | LowCardinality(String)      |

**Why these columns:**
- `severity_id`, `activity_id`: small fixed enum. Dictionary smaller
  than the row count even on the first part.
- `process_name` / `user_name` / `actor_name`: bounded by the number of
  binaries / accounts on a host. A typical Linux box has < 5k unique
  binaries; user_name almost always < 100. Dictionary lookups stay in
  L1 cache.
- `rule_uid` / `rule_name`: bounded by the rule pack size, single-digit
  thousands worst case.

**Why not these columns:**
- `class_uid`: one value per table — no dictionary win.
- `host_id` / `event_id`: UUIDs, high-cardinality on purpose.
  LowCardinality(UUID) isn't supported anyway.
- `pid` / `parent_pid` / `actor_pid` / port columns: integer keys, the
  dictionary overhead exceeds the value width.
- `exec_path` / `cmdline` / `file_path` / `file_name` / `file_hash_sha256`:
  high-cardinality strings, dictionary churn would dominate.
- `protocol`: already LowCardinality in the v1 schema.
- `src_ip` / `dst_ip`: high-cardinality across the fleet; LowCardinality
  on IPs trades a bigger dict for negligible compression on the cold
  path. The hot path is the `ORDER BY` index, not the column dictionary.

### Migration mechanics

`MODIFY COLUMN` rewrites every existing part (a synchronous mutation
queue task) — Phase 3 deployments are still alpha so the rewrite cost
is small. Production deployments running this migration on a hot
table should expect a one-off mutation; the migration is idempotent
from goose's perspective once committed.

Down direction reverts to plain UInt8 / String on the affected
columns and `REMOVE TTL`s the partitions, so a roll-back keeps schema
parity with the v0 shape (lets goose down-migrate cleanly without an
operator manually dropping TTL).

### What we're not doing

- **Row-level TTL on hot columns** (e.g. drop `cmdline` at 7d but
  keep `pid` for 30d). Powerful, complicates the writer, defers to
  Phase 5 along with the storage-hierarchy ADR.
- **Compression codecs.** ClickHouse's default LZ4 is already good;
  ZSTD on `raw` would be a nice-to-have but is part of the same
  Phase 5 conversation.
- **Sharding / replication.** Single-node assumption per ADR-0017
  stays through v1.
- **Surfacing retention as a runtime config knob.** TTL is a
  table-level DDL property; making it config-driven means every
  `slither-server` boot would have to ALTER the table to match the
  config (or the config has to win on conflict). Operators who need
  a non-default TTL run the override `ALTER` once after `slither-ch
  migrate`. This is documented in `docs/install.md` (added in this
  ADR's commit).

## Consequences

- Default 30-day retention bounds storage growth predictably; the
  storage budget for a 50-host fleet at 36k events/s × 4 tables ×
  150 B × 30 d ≈ 60 TB without LowCardinality, dropping to roughly
  6-10 TB with the cardinality tuning across the dictionary-bound
  columns.
- Operators have a single place (`ALTER TABLE … MODIFY TTL …`) to
  override per class. The 30-day default is recorded only in the
  migration; there is intentionally no `clickhouse.retention` config
  knob to keep server boot stateless.
- The `raw` column stays untouched. Dropping it after the column
  projection stabilises is a Phase 5 conversation per ADR-0031.
- Phase 5 may layer on tiered storage (`TTL ... TO VOLUME 'cold'`)
  and recompression. Both are additive.

## References

- ADR-0017 (single-node CH choice)
- ADR-0031 (CH schema v1; introduced the per-class table layout)
- IMPLEMENTATION.md §5.1 task #68
- Phase 2 §10.4 (deferred-questions tracker)
- Phase 5 follow-up: re-examine #59 cold-start hybrid once retention
  is live (IMPLEMENTATION.md §7).
