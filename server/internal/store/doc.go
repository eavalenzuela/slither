// Package store groups the server's backing stores.
//
// Phase 2 §4.1: scaffolded in #31. Subpackages land with their owning tasks:
//   - store/pg — Postgres control plane (#32): hosts, users, enrollment tokens,
//     rules, alerts, audit log.
//   - store/ch — ClickHouse event store (#38): per-class OCSF tables + batched
//     writer driven off the ingest bus.
package store
