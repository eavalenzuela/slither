-- +goose Up
-- Phase 6 #112: tamper-chain cross-check. The agent's selfprotect
-- ChainWriter emits a ChainSummary{last_seq, last_hash, count, since,
-- observed_at} every 5 minutes. The server records every received
-- summary here so operators can inspect chain health per host, and so
-- a follow-up summary can be compared against the prior window's
-- observed_at when computing expected counts.
--
-- count_observed is the count the agent reported. count_expected is
-- the server's count of equivalent rows (response_actions + CH
-- detection_findings) in [since, observed_at). mismatch is true when
-- count_observed != count_expected; the verifier also writes a
-- `chain.mismatch` audit_log row on those, so this table doubles as
-- the source for the `/hosts/{id}/chain-status` page.
--
-- No FK to hosts (id, uuid) so a revoked or deleted host's history
-- survives — operators sometimes audit a chain after a compromise has
-- already been remediated.

CREATE TABLE chain_summaries (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         uuid        NOT NULL,
    last_seq        bigint      NOT NULL CHECK (last_seq >= 0),
    last_hash       text        NOT NULL,
    count_observed  bigint      NOT NULL CHECK (count_observed >= 0),
    count_expected  bigint      NOT NULL CHECK (count_expected >= 0),
    mismatch        boolean     NOT NULL DEFAULT false,
    since_at        timestamptz NOT NULL,
    observed_at     timestamptz NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now()
);

-- Console queries: "show me this host's recent summaries newest-first".
CREATE INDEX chain_summaries_host_received_idx
    ON chain_summaries (host_id, received_at DESC);

-- "show me only the mismatches" filter.
CREATE INDEX chain_summaries_mismatch_idx
    ON chain_summaries (host_id, received_at DESC)
    WHERE mismatch = true;

-- +goose Down
DROP TABLE chain_summaries;
