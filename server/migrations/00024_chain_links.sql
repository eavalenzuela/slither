-- +goose Up
-- Phase 7 / ADR-0042: tamper-chain link witness.
--
-- Phase 6 #112 (migration 00018) could only cross-check the agent's
-- chain by COUNT, because the agent's per-record hash covers a local
-- wall-clock `ts` the server cannot reconstruct. That left
-- edit-then-relink undetectable: rewrite one record, recompute its
-- record_hash, re-link every record after it, and the file still
-- self-verifies at the same length.
--
-- ADR-0042 closes it by having the agent ship each record's
-- (seq, kind, prev_hash, record_hash) tuple with its 5-minute summary.
-- This table is the server's append-only witness of those tuples. It
-- does not let the server recompute a hash — it lets the server refuse
-- to accept a DIFFERENT hash for a seq it has already seen, and anchor
-- each new segment's prev_hash on the last record_hash it witnessed.
-- Relinking necessarily changes the tail, so it surfaces on the next
-- summary.
--
-- Rows are immutable once written. The verifier inserts with
-- ON CONFLICT DO NOTHING and compares rather than updating, so a
-- compromised agent cannot rewrite history it has already reported.
-- There is deliberately no UPDATE path in the store.
--
-- No FK to hosts, matching chain_summaries (00018): a revoked or
-- deleted host's chain history has to survive, because that is exactly
-- when someone audits it.

CREATE TABLE chain_links (
    host_id       uuid        NOT NULL,
    seq           bigint      NOT NULL CHECK (seq >= 0),
    kind          text        NOT NULL,
    prev_hash     text        NOT NULL,
    record_hash   text        NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, seq)
);

-- The verifier's hottest query is "what is the newest link I hold for
-- this host?" (the continuity anchor). The PK's (host_id, seq) order
-- already serves it as a backward index scan, so no extra index — the
-- table is write-heavy and every index is paid on every append.

-- Retention: chain_links grows with response actions + findings, not
-- with raw events, so a 500-host fleet accrues on the order of tens of
-- MB/year. It is pruned alongside audit_log by the operator retention
-- job rather than by a TTL here, so that a host under investigation
-- keeps its witness for as long as the audit trail it corroborates.

-- Link-verification outcome for each received summary. Kept on
-- chain_summaries (rather than a second table) because it is a
-- property of the summary, and the console renders both together on
-- /hosts/{id}/chain-status.
--
-- link_status is one of:
--   none      — agent shipped no links (pre-ADR-0042 agent). The row
--               degrades to Phase 6 #112 count-only semantics.
--   ok        — links replayed clean and chained onto the witness.
--   truncated — agent's bounded link buffer overflowed; the tail is
--               intact, the head of the window is missing by design.
--   gap       — sequence hole between the witness and this segment
--               that truncation does not explain. Informational.
--   broken    — linkage violation or a contradicted record_hash. This
--               is the tamper signal; the verifier also fires a
--               `chain.link_mismatch` audit row at severity 5 and
--               writes NOTHING to chain_links for the segment.
ALTER TABLE chain_summaries
    ADD COLUMN links_reported bigint NOT NULL DEFAULT 0
        CHECK (links_reported >= 0),
    ADD COLUMN links_new      bigint NOT NULL DEFAULT 0
        CHECK (links_new >= 0),
    ADD COLUMN link_status    text   NOT NULL DEFAULT 'none'
        CHECK (link_status IN ('none', 'ok', 'truncated', 'gap', 'broken')),
    ADD COLUMN link_detail    text   NOT NULL DEFAULT '';

-- "Show me every host whose chain linkage broke" — the query an
-- operator runs first during an incident.
CREATE INDEX chain_summaries_link_broken_idx
    ON chain_summaries (host_id, received_at DESC)
    WHERE link_status = 'broken';

-- +goose Down
DROP INDEX IF EXISTS chain_summaries_link_broken_idx;
ALTER TABLE chain_summaries
    DROP COLUMN IF EXISTS link_detail,
    DROP COLUMN IF EXISTS link_status,
    DROP COLUMN IF EXISTS links_new,
    DROP COLUMN IF EXISTS links_reported;
DROP TABLE chain_links;
