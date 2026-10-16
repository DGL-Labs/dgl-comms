-- C-1b (G5 round 1): absolute session lifetime and tighter grants.
-- Runs as pingzo_owner. Add-only.

-- The time the first session of a refresh chain was made. Each rotation
-- carries it forward, so a chain ends 90 days after it began.
ALTER TABLE sessions
  ADD COLUMN chain_started_at timestamptz NOT NULL DEFAULT now();
