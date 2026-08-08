# ADR-0042: Tamper-chain record-level verification via link replication

**Status:** accepted

**Date:** 2026-08-07

## Context

Phase 5 #95 gave the agent a tamper-evident hash chain at
`/var/lib/slither/log.chain`. Each terminal response-action transition
and each emitted detection finding appends one record; every record's
`prev_hash` is the previous record's `record_hash`, and `record_hash` is
`sha256("seq|ts|kind|summary|prev_hash")`.

Phase 6 #112 added a server-side cross-check, but only a **count-based**
one. Every 5 minutes the agent ships a `ChainSummary{last_seq, last_hash,
count, since, observed_at}`; the server counts equivalent
`pg.response_actions` + CH `ocsf_detection_finding_2004` rows for the same
window and flags a delta. `last_hash` is stored verbatim and never
checked, because the canonical hash input includes `ts` — an agent-local
RFC3339Nano wall-clock the server cannot reconstruct from its own rows.

That leaves a real hole, recorded as a Phase 7 carry-over in
IMPLEMENTATION.md §9. Count-based detection catches truncation and
replay-then-extend. It does **not** catch a record-level edit: an
attacker with local root can rewrite one record's `summary`, recompute
that record's `record_hash`, and re-link every subsequent record. The
result is internally consistent — `slither-agent verify-chain` passes,
the count is unchanged, and the server sees nothing.

§9 framed the fix as a choice between two options:

- **(a)** drop `ts` from the hash inputs and key on a server-derivable
  field per record kind (OCSF `time` for findings, pg `created_at` for
  response actions), so the server can recompute `record_hash` outright.
- **(b)** carry the agent's per-record hash to the server so the chain can
  be replayed link-by-link without re-deriving the hashed fields.

## Decision

Take **(b)**, realised as **link replication**: the agent ships the
`(seq, kind, prev_hash, record_hash)` tuple for every record appended in
the summary window, and the server persists them in a new
`chain_links` table. The server is then an independent, append-only
**witness** of the chain, and verifies three properties on every
received segment:

1. **Continuity with the witness** — the segment's first link must have
   `seq == witness.last_seq + 1` and `prev_hash == witness.last_hash`.
2. **Internal linkage** — within the segment, `seq` increments by one and
   `prev_hash[i] == record_hash[i-1]`.
3. **Immutability of already-witnessed links** — a link re-reported for a
   `seq` the server has already stored must carry the identical
   `record_hash`.

Any violation writes a `chain.link_mismatch` audit row at severity 5
(critical) and marks the summary row mismatched. Count-based checking is
retained unchanged and runs alongside; the two catch different things.

The canonical hash input is **not** changed. `ts` stays hashed.

## Consequences

**Easier.**

- Record-level edits become server-detectable. Rewriting record *n* on
  disk changes its `record_hash`, but the server already holds the
  original under `seq = n` and rejects the contradiction. The attacker
  would have to have compromised the host *before* the record was first
  shipped, which shrinks the window from "any time before the audit" to
  "under 5 minutes".
- Whole-chain replacement is caught. A rebuilt chain restarts at `seq=0`
  with `prev_hash = zeroHash`, which fails the continuity check against a
  witness whose `last_seq` is nonzero.
- Cross-restart stitching is free. `prev_hash` linkage is continuous
  across summary boundaries *and* across agent restarts, because
  `OpenChain`'s `recover()` resumes from the last on-disk record. The
  server needs no restart-awareness.
- On-agent tamper evidence is preserved in full. `ts` remains hashed, so
  `slither-agent verify-chain` keeps detecting a back-dated record —
  which option (a) would have silently given up.

**Harder.**

- One new pg table and a per-record write path. At the observed rates
  this is small: `chain_links` rows are ~120 bytes and only response
  actions and findings append, not raw events. Retention is bounded by a
  migration-declared cleanup contract (below).
- The agent must buffer the window's links in memory between ticks.
  Bounded at `maxWindowLinks` (512, ~75 KiB). On overflow the buffer
  drops from the **head**, not the tail, and sets `links_truncated`. That
  direction is deliberate: the tail is what the next segment's continuity
  check anchors on, so losing it would break the witness permanently,
  while losing the head costs one window's record-level coverage. The
  server reports the resulting hole as `truncated` rather than as an
  unexplained `gap`.
- Two places where the window could silently evaporate had to be closed,
  because a hole in the witness is not merely lost coverage — every
  later segment would report a gap against it:
  - **Restart.** `OpenChain`'s existing `recover()` scan now also
    re-seeds the link buffer from the tail of the on-disk chain, so the
    first segment after a bounce overlaps the last one shipped before it.
    Re-reported links cost nothing (`ON CONFLICT DO NOTHING`) and buy a
    second, independent contradiction check.
  - **Dropped summary.** The summary sink is a capacity-4 channel that
    drops rather than blocks. `ChainWriter.ReturnWindow` folds an
    unshipped snapshot — links *and* count — back into the live window so
    the next tick re-ships it.
- A `gap` therefore now means something. With both holes closed it is no
  longer the routine consequence of a restart, so it is recorded and
  surfaced. It is still not a mismatch and fires no audit row: the links
  present are internally valid, and a first segment from an agent
  re-enrolled with a pre-existing chain legitimately produces one.

**Follow-up work / new constraints.**

- `ChainSummary` gains two additive fields inside the frozen `slither.v1`
  wire (ADR-0011): `repeated ChainLink links` and `bool links_truncated`.
  Additive proto3 fields are the documented mechanism; v0 agents that
  never emit them degrade to exactly the Phase 6 #112 count-only
  behaviour, and the server treats an empty `links` list as "count-only
  agent" rather than as a mismatch.
- **No `log.chain` on-disk format bump.** §9 anticipated one for either
  option. (b) does not need it: everything the server needs is already
  in each record, and the writer only has to remember what it wrote.
  Not bumping the format means no agent-side migration and no
  compatibility matrix between agent versions and existing chain files.
- Retention: `chain_links` is pruned by the same operator-run retention
  job as `audit_log`, so a host under investigation keeps its witness for
  as long as the audit trail it corroborates. Migration 00024 declares the
  intent; wiring the prune into the scheduled job is a follow-up for when
  a real fleet's growth rate is measurable, not before.
- The verifier reaches its link store by capability upgrade — the real
  `*pg.Store` satisfies `ChainLinkStore`, pinned by a compile-time
  assertion so dropping a method is a build failure rather than a silent
  downgrade to count-only. A store that genuinely lacks it records
  `link_status = none` with a reason instead of claiming `ok`.
- Both checks write to one `mismatch` flag on `chain_summaries`, so
  existing consumers (`ListChainMismatches`, the host page's badge) light
  up for a link break without knowing link_status exists. The specific
  reason lives in `link_status` / `link_detail`.

## Alternatives considered

- **Option (a), drop `ts` from the hash inputs.** Rejected. It weakens
  on-agent evidence — an unhashed `ts` is freely editable, so back-dating
  a record to slip past a `--since` window becomes undetectable. It also
  does not actually deliver a full recompute: the hash input still
  contains the agent-shaped `summary` JSON, which is not byte-equal to
  what the server stored in CH/pg, so the server would still be unable to
  recompute `record_hash` end-to-end.
- **Option (b) as literally worded — stamp `record_hash` onto each CH
  detection-finding and pg response-action row.** Rejected on blast
  radius for no added power. It requires a ClickHouse migration on an
  ADR-0007/ADR-0031-frozen OCSF table, adds chain fields to the finding
  and `ResponseResult` messages, and couples the chain writer's ordering
  to the event sink's batch flush. It yields exactly the same
  verification power as shipping the links directly, because the server
  still cannot recompute a hash it has no canonical input for — it can
  only replay linkage either way.
- **Sign each record with an agent key.** Rejected, and already rejected
  in the Phase 5 #95 header comment: the key lives on the host, so a
  local-root attacker who can rewrite the chain can also sign the
  rewrite. Remote attestation is the real answer and is out of scope.
- **Ship the whole chain periodically.** Rejected — unbounded growth on
  the wire for a property that incremental links already give.

## References

- IMPLEMENTATION.md §9 — "Tamper-chain hash recompute (carry-over from
  #112)", the item this ADR closes.
- IMPLEMENTATION.md §7 (Phase 5 #95) — the original hash-chain design.
- IMPLEMENTATION.md §8 (Phase 6 #112) — the count-based cross-check this
  builds on.
- ADR-0011 — gRPC/mTLS transport and the `slither.v1` additive-change
  discipline.
- ADR-0022 — protection-first principle.
- `docs/threat-model.md` Surface 4 — the Tampering row, whose
  "Partially defended" status this ADR narrows.
