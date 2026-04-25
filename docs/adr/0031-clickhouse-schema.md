# ADR-0031: ClickHouse schema v1 + migration tool

**Status:** accepted

**Date:** 2026-04-25

## Context

Phase 2 §4.1 task #38 picks the initial event-store schema and the tool
that applies it. The schema is exposed to operator queries via the
events search page (#43) and to the writer pool, so getting it
roughly-right early matters more than getting it final-right — Phase 3
revisits cardinality + retention once production volumes land.

## Decision

### Tables — one per OCSF class shipped in Phase 1

| Table                                | OCSF class_uid | Phase 1 source        |
|--------------------------------------|----------------|-----------------------|
| `ocsf_process_activity_1007`         | 1007           | sched_process_*       |
| `ocsf_file_system_activity_1001`     | 1001           | per-syscall file BPF  |
| `ocsf_network_activity_4001`         | 4001           | tcp_connect           |
| `ocsf_detection_finding_2004`        | 2004           | rule engine           |

One table per class (rather than a single events table with a
discriminator) buys two things:

1. Class-specific materialised columns for hot-path queries without
   forcing every query to live behind a `class_uid = N` filter the
   skip-index can't always exploit.
2. Cheap Phase-3 retention tuning per class: detections are kept
   forever, network activity may roll off in 90 days.

The cost is more migration files when OCSF evolves. Acceptable — OCSF
class additions are rare on this scale and Phase 5 is the migration
harness checkpoint anyway.

### Shared columns

Every table starts with the same six columns in the same order:
`event_id UUID`, `host_id UUID`, `observed_at DateTime64(9)`,
`collected_at DateTime64(9)`, `class_uid UInt32`, `severity_id UInt8`,
`raw String`. `raw` carries the canonical OCSF JSON the agent sent —
the column-projection above is for query speed; truth lives in `raw`.

### Engine / partitioning / ORDER BY

```
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (host_id, observed_at, event_id)
```

Daily partitions keep retention DDL trivial. `ORDER BY (host_id,
observed_at, event_id)` matches the dominant query shape — events for
host X in time range Y — and the trailing `event_id` keeps the index
keys unique so the cursor pagination in #43 can use
`(observed_at, event_id) < (a, b)` for stable, skip-cheap paging.

### Migration tool — goose, not golang-migrate

The Phase 2 plan called for `golang-migrate/migrate`, but goose v3 has
a working `clickhouse` dialect and we already use goose for the
Postgres control plane (#32 / ADR-0030). One migration toolchain across
both stores is cheaper to maintain than two, and the SQL flavour
difference is irrelevant once the dialect is set — goose just dispatches
to the registered `database/sql` driver.

`server/clickhouse/migrations/*.sql` are embedded via `embed.FS` and
applied by `ch.Migrate(ctx, dsn)` (constructor) or `slither-ch migrate`
(CLI, mirrors `slither-db`). A goose-managed `goose_db_version` table
in the same database tracks state.

### Driver — `clickhouse-go/v2`

Native protocol, prepared inserts via `db.PrepareBatch`, async insert
support. The pgx-equivalent of the CH ecosystem; well-supported by
ClickHouse Inc. The HTTP driver was rejected — wider compatibility but
materially slower for bulk inserts at our batch sizes.

### Writer

`server/internal/store/ch.Writer` is a single goroutine per class that
subscribes to `ingest.Bus`, accumulates rows in a per-class buffer, and
flushes when either the row count hits `batch_size` (default 10,000)
or `flush_interval` elapses (default 2s) — whichever fires first. The
writer issues plain synchronous `INSERT INTO ... VALUES` against a
prepared batch — `async_insert=1` was considered but discarded for v1:
our writer already batches, and async_insert costs read-your-writes
determinism (server-side queue flush is asynchronous to the client
return). Phase 3 may revisit if multiple slither replicas need to share
a CH cluster, where async_insert's cross-writer pooling becomes
material.

Backpressure: the bus drops on full subscriber, so a stalled CH server
costs visibility into recent events for as long as the buffer is full,
but never stalls ingest itself. Drops are tracked under
`telemetry.IncDropSubscriber`.

## Consequences

- Schema additions (new OCSF classes in Phase 3+) require a new
  migration file and a corresponding writer registration. Both are
  one-line edits.
- Adding columns is non-destructive (`ALTER TABLE ... ADD COLUMN`) but
  removes go through Phase 5's migration harness.
- `raw` doubling the storage cost is intentional for v1; Phase 3 can
  drop it once the column projection is stable.
- Reset is not exposed by `slither-ch` (unlike `slither-db reset`):
  CH has no equivalent of pg's `truncate-and-replay` that a fresh
  developer needs more often than they need protection from
  accidentally wiping a real cluster. The down-migrations are still
  present so goose can roll back individual versions.
