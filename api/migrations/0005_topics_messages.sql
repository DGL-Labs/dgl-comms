-- C-1d A1, A2, A8: topics, subscriptions, the topic key upgrade, messages and
-- fanout_jobs. Runs as pingzo_owner. Add-only.
-- Every table below states its grants. The default privileges from 0001 would
-- hand pingzo_app full DML on a new table, so each new table is revoked first
-- and then granted exactly what the app needs.

CREATE TABLE topics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  last_seq bigint NOT NULL DEFAULT 0,
  oldest_kept_seq bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- The target of the composite foreign keys below: a child row can only name
  -- a topic of its own workspace.
  UNIQUE (id, workspace_id)
);
CREATE INDEX topics_workspace_id_idx ON topics (workspace_id);

CREATE TABLE subscriptions (
  account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  topic_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  muted boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, topic_id),
  FOREIGN KEY (topic_id, workspace_id)
    REFERENCES topics (id, workspace_id) ON DELETE CASCADE
);
CREATE INDEX subscriptions_topic_idx ON subscriptions (topic_id, workspace_id);
CREATE INDEX subscriptions_workspace_id_idx ON subscriptions (workspace_id);

-- topic_keys (from 0003): the composite foreign key, by a plain ADD CONSTRAINT.
-- There is no DELETE first: an orphan row (a topic_id with no topic) makes this
-- migration fail, which is the safe outcome. rotated_at marks a key that a
-- rotation replaced; it stays valid until its own expires_at (at most 24 hours
-- on). expires_at stays nullable, but the app gives new keys 365 days.
ALTER TABLE topic_keys ADD COLUMN rotated_at timestamptz NULL;
ALTER TABLE topic_keys
  ADD CONSTRAINT topic_keys_topic_fk FOREIGN KEY (topic_id, workspace_id)
    REFERENCES topics (id, workspace_id) ON DELETE CASCADE;
CREATE INDEX topic_keys_topic_idx ON topic_keys (topic_id, workspace_id);

CREATE TABLE messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  topic_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  seq bigint NOT NULL,
  sender_account_id uuid NULL,
  sender_key_id text NULL,
  sender_label text NOT NULL,
  sender_kind text NOT NULL CHECK (sender_kind IN ('person', 'key', 'system')),
  title text NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (topic_id, seq),
  FOREIGN KEY (topic_id, workspace_id)
    REFERENCES topics (id, workspace_id) ON DELETE CASCADE
);
CREATE INDEX messages_workspace_id_idx ON messages (workspace_id);

-- Written at publish. Nothing consumes it until C-1f.
CREATE TABLE fanout_jobs (
  id bigserial PRIMARY KEY,
  message_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'leased', 'done', 'dead')),
  attempts integer NOT NULL DEFAULT 0,
  next_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX fanout_jobs_message_id_idx ON fanout_jobs (message_id);
CREATE INDEX fanout_jobs_workspace_id_idx ON fanout_jobs (workspace_id);

-- Grants for pingzo_app, table by table. topic_keys keeps its grants from 0003
-- (SELECT, INSERT, UPDATE, DELETE, which cover the new column).
REVOKE ALL ON topics, subscriptions, messages, fanout_jobs FROM pingzo_app;
REVOKE ALL ON SEQUENCE fanout_jobs_id_seq FROM pingzo_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON topics TO pingzo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON subscriptions TO pingzo_app;
GRANT SELECT, INSERT ON messages TO pingzo_app;
GRANT SELECT, INSERT ON fanout_jobs TO pingzo_app;
-- The one sequence grant: fanout_jobs.id is a bigserial, so INSERT needs it.
GRANT USAGE ON SEQUENCE fanout_jobs_id_seq TO pingzo_app;

-- Row-level security with the template policy from 0003: USING and WITH CHECK
-- are identical. FORCE binds the table owner too. topic_keys already has its
-- policy; the two ALTERs on it below only restate that it is enabled and forced.
ALTER TABLE topics ENABLE ROW LEVEL SECURITY;
ALTER TABLE topics FORCE ROW LEVEL SECURITY;
CREATE POLICY topics_workspace ON topics
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_workspace ON subscriptions
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );

ALTER TABLE topic_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE topic_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
CREATE POLICY messages_workspace ON messages
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );

ALTER TABLE fanout_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fanout_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY fanout_jobs_workspace ON fanout_jobs
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );
