-- +goose Up
-- Postgres LISTEN/NOTIFY plumbing for the rules table. The control plane
-- (#39) opens a dedicated connection that LISTENs on `rules_changed` so
-- inserts/updates/deletes propagate to every connected agent within
-- ~1 second without polling. The trigger fires after every row-level
-- change; the payload is intentionally empty since the channel itself
-- is the event signal — handlers re-read the table to pick up the new
-- state, which keeps the trigger trivial and avoids JSON encoding.

-- +goose StatementBegin
CREATE FUNCTION rules_notify_changed() RETURNS trigger AS $$
BEGIN
    NOTIFY rules_changed;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER rules_notify_changed
AFTER INSERT OR UPDATE OR DELETE ON rules
FOR EACH ROW
EXECUTE FUNCTION rules_notify_changed();

-- +goose Down
DROP TRIGGER rules_notify_changed ON rules;
DROP FUNCTION rules_notify_changed;
