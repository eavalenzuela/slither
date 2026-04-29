-- +goose Up
-- Phase 4 #72: per-host response-action policy. Default-detect-only on
-- every freshly enrolled host — every column defaults to false, so a
-- host that never had a row inserted still resolves to all-false via
-- COALESCE on the read side. ADR-0034 picks per-action-class booleans
-- rather than one global flag so the operator can grant the cheap
-- actions (collect, kill_process) widely while keeping the disruptive
-- ones (isolate) gated to a narrow on-call group.
--
-- `allow_unisolate` is intentionally absent — reverse actions inherit
-- their parent's permission so an operator can never trap themselves
-- in a state they can't roll back. The dispatcher checks
-- allow_isolate for both ISOLATE_HOST and UNISOLATE_HOST.
--
-- NOTIFY trigger mirrors rules_notify_changed (#39 / migration 00008)
-- so the control hub can push HostPolicy updates to connected agents
-- on the same NOTIFY-driven path that handles ruleset refreshes.
CREATE TABLE host_response_policies (
    host_id            uuid PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    allow_kill_process boolean     NOT NULL DEFAULT false,
    allow_kill_tree    boolean     NOT NULL DEFAULT false,
    allow_quarantine   boolean     NOT NULL DEFAULT false,
    allow_isolate      boolean     NOT NULL DEFAULT false,
    allow_collect      boolean     NOT NULL DEFAULT false,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid        REFERENCES users (id) ON DELETE SET NULL
);

-- +goose StatementBegin
CREATE FUNCTION host_response_policies_notify_changed() RETURNS trigger AS $$
BEGIN
    NOTIFY host_response_policies_changed;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER host_response_policies_notify_changed
AFTER INSERT OR UPDATE OR DELETE ON host_response_policies
FOR EACH ROW
EXECUTE FUNCTION host_response_policies_notify_changed();

-- +goose Down
DROP TRIGGER host_response_policies_notify_changed ON host_response_policies;
DROP FUNCTION host_response_policies_notify_changed;
DROP TABLE host_response_policies;
