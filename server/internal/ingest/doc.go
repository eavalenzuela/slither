// Package ingest owns the in-process event bus that fans out agent events
// to subscribers (ClickHouse writer, live-tail SSE, future detection engine).
//
// Phase 2 §4.1: scaffolded in #31; Session handler + bus + subscriber
// registry land in #37.
package ingest
