-- +goose Up
-- Phase 3 #60 — per-rule alert dedupe window. NULL means "no dedupe":
-- fast-retriggering rules (a brute-force-ssh count rule, an IOC hit
-- on a beacon) carry signal in their retrigger frequency, and
-- collapsing them into one alert per host loses that signal. Operators
-- opt-in to dedupe per rule by setting a window in seconds.
--
-- The alert sink (#60) consults this column on every InsertAlert: if
-- non-NULL and a recent alert exists with the same (rule_uid,
-- host_id) inside the window, the new finding is suppressed.
-- Migration 00011 (`00011_iocs.sql`) is reserved for #66; this jump
-- to 00012 keeps the number stable when the IOC table lands.

ALTER TABLE rules
    ADD COLUMN dedupe_window_secs int;

ALTER TABLE rules
    ADD CONSTRAINT rules_dedupe_window_secs_chk
    CHECK (dedupe_window_secs IS NULL OR dedupe_window_secs > 0);

-- +goose Down
ALTER TABLE rules DROP CONSTRAINT rules_dedupe_window_secs_chk;
ALTER TABLE rules DROP COLUMN dedupe_window_secs;
