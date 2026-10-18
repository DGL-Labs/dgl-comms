-- C-1d A3, A4, A5: publish and limits. Runs as pingzo_owner. Add-only.
-- Every table below states its grants. The default privileges from 0001 would
-- hand pingzo_app full DML on a new table, so each new table is revoked first
-- and then granted exactly what the app needs.

-- Token buckets, one row per counter: ws:<workspace id>, acct:<account id> and
-- ip:<address>. Counters only, no row of a tenant: no row-level security. The
-- ip: and acct: rows are personal data and have no retention yet
-- (docs/KNOWN-GAPS.md).
CREATE TABLE rate_buckets (
  bucket text PRIMARY KEY,
  tokens numeric NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Messages published by a workspace on one day. No row-level security: the
-- debit runs before any context exists. It goes with the workspace.
CREATE TABLE workspace_usage_daily (
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  day date NOT NULL,
  count integer NOT NULL,
  PRIMARY KEY (workspace_id, day)
);

-- Messages published by non-internal workspaces, per minute and shard, so that
-- writers do not queue on one row. The day's total is the sum over the rows
-- from today. No row-level security (a number, no workspace).
CREATE TABLE global_usage_minute (
  minute timestamptz NOT NULL,
  shard smallint NOT NULL CHECK (shard BETWEEN 0 AND 15),
  count integer NOT NULL,
  PRIMARY KEY (minute, shard)
);

-- One row per (caller, Idempotency-Key). caller is a:<account id> or
-- k:<key id>. A row older than 24 hours may be taken over by a new publish.
CREATE TABLE idempotency_keys (
  caller text NOT NULL,
  key text NOT NULL CHECK (key ~ '^[ -~]{1,200}$'),
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  message_id uuid NULL REFERENCES messages (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (caller, key)
);
CREATE INDEX idempotency_keys_workspace_id_idx ON idempotency_keys (workspace_id);
CREATE INDEX idempotency_keys_message_id_idx ON idempotency_keys (message_id);

-- service_limits: the global daily ceiling and the two pause flags. The table
-- stays read-only for pingzo_app (SELECT from 0003, unchanged): the flags are
-- set by the maintainer role (C-1d A6) or by the owner.
ALTER TABLE service_limits
  ADD COLUMN max_msgs_per_day_total integer NOT NULL DEFAULT 200000
    CHECK (max_msgs_per_day_total >= 0),
  ADD COLUMN signup_paused boolean NOT NULL DEFAULT false,
  ADD COLUMN publish_paused_non_internal boolean NOT NULL DEFAULT false;

-- Grants for pingzo_app, table by table. Nothing is deleted by the app:
-- retention for these tables comes at C-1g.
REVOKE ALL ON rate_buckets, workspace_usage_daily, global_usage_minute,
  idempotency_keys FROM pingzo_app;

GRANT SELECT, INSERT, UPDATE ON rate_buckets TO pingzo_app;
GRANT SELECT, INSERT, UPDATE ON workspace_usage_daily TO pingzo_app;
GRANT SELECT, INSERT, UPDATE ON global_usage_minute TO pingzo_app;
GRANT SELECT, INSERT, UPDATE ON idempotency_keys TO pingzo_app;

-- Row-level security on idempotency_keys only, with the template policy from
-- 0003: USING and WITH CHECK are identical. FORCE binds the table owner too.
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_keys_workspace ON idempotency_keys
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );
