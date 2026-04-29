-- +goose Up
-- IOC feed storage for Phase 3 #66 / #67. Each row is one feed: a
-- named bag of indicators (SHA-256 hashes, IPv4/IPv6 addresses, or
-- domains) Sigma rules reference via `|ioc` predicates.
--
-- ADR-0018 predicate 3 caps feeds at 100k entries — an edge agent
-- holds the full set in memory (~10 MB for 100k SHA-256), and oversize
-- feeds force the rule server-only. The cap is enforced both as a
-- CHECK and again in the pg.InsertIOCFeed / UpdateIOCFeed helpers so a
-- direct INSERT can't blow past it.
--
-- feed_id is the wire identity carried in `ioc:<feed_id>` rule
-- references; uniqueness is structural so the compiler's lookup is a
-- single row. updated_at advances on every entry change so #67's
-- agent-side reload notice can spot real changes via NOTIFY.
CREATE TABLE iocs (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id    text        NOT NULL UNIQUE,
    name       text        NOT NULL,
    kind       text        NOT NULL CHECK (kind IN ('sha256','ipv4','ipv6','domain')),
    entries    text[]      NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid        REFERENCES users (id) ON DELETE SET NULL,
    CHECK (cardinality(entries) <= 100000)
);

CREATE INDEX iocs_kind_idx ON iocs (kind);

-- +goose Down
DROP TABLE iocs;
