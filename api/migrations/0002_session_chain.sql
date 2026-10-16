-- C-1b (G5 round 1): absolute session lifetime and tighter grants.
-- The two tables below record events and are add-only for the app.
-- Runs as pingzo_owner. Add-only.

-- The time the first session of a refresh chain was made. Each rotation
-- carries it forward, so a chain ends 90 days after it began.
ALTER TABLE sessions
  ADD COLUMN chain_started_at timestamptz NOT NULL DEFAULT now();

-- Event rows are never changed after they are written. pingzo_app keeps
-- SELECT, INSERT and DELETE on both.
REVOKE UPDATE ON signup_events, login_failures FROM pingzo_app;
