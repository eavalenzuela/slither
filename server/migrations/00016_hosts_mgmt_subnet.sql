-- +goose Up
-- Phase 4 #80: per-host management-subnet override for ISOLATE_HOST.
-- The agent isolates by appending a netfilter chain that allows
-- established+related + lo + the mgmt_subnet, and drops everything
-- else. NULL means "agent autoderives from /proc/net/route at
-- isolate time"; explicit CIDR (e.g. "172.31.0.0/16") wins.
--
-- Validation is loose by design: rule shapes vary across cloud
-- environments + on-prem deployments, and a too-strict CHECK would
-- block legitimate configurations. Bad CIDR surfaces at apply time
-- as a FAILED ResponseResult with a clear detail.
ALTER TABLE hosts
    ADD COLUMN mgmt_subnet text;

-- +goose Down
ALTER TABLE hosts
    DROP COLUMN mgmt_subnet;
