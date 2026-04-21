-- Slither event-store schema bootstrap.
-- Phase 0: create the database. Event tables arrive in Phase 2 keyed on
-- (host_id, class_id, time) with a MergeTree engine tuned for time-range
-- queries + low-cardinality class filter.

CREATE DATABASE IF NOT EXISTS slither;
