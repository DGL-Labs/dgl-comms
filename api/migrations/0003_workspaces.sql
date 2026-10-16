-- C-1c: workspaces, members, invitations, limits, topic keys, audit log, roles
-- and row-level security. Runs as pingzo_owner. Add-only.
-- Every table below states its grants. The default privileges from 0001 would
-- hand pingzo_app full DML on a new table, so each table is revoked first and
-- then granted exactly what the app needs.

CREATE TABLE workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES accounts (id),
  -- r4 has no name column. The app needs one, so it is added here.
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  kind text NOT NULL CHECK (kind IN ('client', 'team', 'dgl_internal')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX workspaces_owner_id_idx ON workspaces (owner_id);

CREATE TABLE workspace_limits (
  workspace_id uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  max_topics integer NOT NULL DEFAULT 3,
  max_members integer NOT NULL DEFAULT 5,
  max_keys integer NOT NULL DEFAULT 5,
  msgs_per_day integer NOT NULL DEFAULT 1000,
  msgs_per_min integer NOT NULL DEFAULT 60,
  max_body_bytes integer NOT NULL DEFAULT 2048,
  retention_days integer NOT NULL DEFAULT 30
);

-- Three roles only (C1C ADDENDUM-2). r3 also lists viewer; it is left out.
CREATE TABLE members (
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, account_id)
);
CREATE UNIQUE INDEX members_one_owner_idx ON members (workspace_id)
  WHERE role = 'owner';
CREATE INDEX members_account_id_idx ON members (account_id);

CREATE TABLE invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  invited_by uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  email citext NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'member')),
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitations_workspace_id_idx ON invitations (workspace_id);

-- r4, minimal (C1C ADDENDUM-1 D2). C-1d adds topics and the composite FK.
CREATE TABLE topic_keys (
  id text PRIMARY KEY CHECK (id ~ '^pz_[a-z2-7]{8}$'),
  key_hash bytea NOT NULL,
  topic_id uuid NOT NULL,
  workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  expires_at timestamptz NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX topic_keys_workspace_id_idx ON topic_keys (workspace_id);

-- r4, minimal: one row. The other columns come at C-1d.
CREATE TABLE service_limits (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  max_workspaces_total integer NOT NULL DEFAULT 2000 CHECK (max_workspaces_total >= 0)
);
INSERT INTO service_limits (id) VALUES (true);

-- Append-only by grants. target is an id, never an email.
CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  actor_account_id uuid NULL,
  workspace_id uuid NULL,
  action text NOT NULL,
  target text NULL,
  reason text NULL
);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_account_id, action, at);
CREATE INDEX audit_log_workspace_idx ON audit_log (workspace_id, action, at);

-- Grants for pingzo_app, table by table.
REVOKE ALL ON workspaces, workspace_limits, members, invitations, topic_keys,
  service_limits, audit_log FROM pingzo_app;
REVOKE ALL ON SEQUENCE audit_log_id_seq FROM pingzo_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON workspaces TO pingzo_app;
GRANT SELECT, INSERT ON workspace_limits TO pingzo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON members TO pingzo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON invitations TO pingzo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON topic_keys TO pingzo_app;
GRANT SELECT ON service_limits TO pingzo_app;
GRANT SELECT, INSERT ON audit_log TO pingzo_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO pingzo_app;

-- Row-level security, with FORCE so the table owner is bound too.
-- POLICY TEMPLATE for every workspace-scoped table (C-1d and later reuse this
-- exact form): USING and WITH CHECK are identical.
--   workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
-- The setting is SET LOCAL only, through the helpers in api/src/db.ts. A
-- missing or empty setting gives an empty list, so no row matches.

ALTER TABLE members ENABLE ROW LEVEL SECURITY;
ALTER TABLE members FORCE ROW LEVEL SECURITY;
-- members adds one clause to USING only: a caller reads its own rows, to build
-- the context. WITH CHECK stays workspace-only.
CREATE POLICY members_workspace ON members
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
    OR account_id = nullif(current_setting('app.account_id', true), '')::uuid
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_workspace ON invitations
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );
-- Accepting an invitation: the invitee is not yet a member, so it cannot see
-- the row by workspace. The hash of the token it holds (set by withContext,
-- hex) opens that one row for reading and for marking it used, and nothing
-- else. There is no INSERT or DELETE form of this policy.
CREATE POLICY invitations_by_token_select ON invitations FOR SELECT
  USING (token_hash = decode(nullif(current_setting('app.invite_hash', true), ''), 'hex'));
CREATE POLICY invitations_by_token_update ON invitations FOR UPDATE
  USING (token_hash = decode(nullif(current_setting('app.invite_hash', true), ''), 'hex'));

ALTER TABLE topic_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE topic_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY topic_keys_workspace ON topic_keys
  USING (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  )
  WITH CHECK (
    workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
  );

-- pingzo_keyresolver: NOLOGIN and BYPASSRLS (created by the bootstrap). It
-- reads topic_keys and two columns of workspaces, owns only the function
-- below, and has nothing else.
GRANT USAGE ON SCHEMA public TO pingzo_keyresolver;
GRANT SELECT ON topic_keys TO pingzo_keyresolver;
GRANT SELECT (id, status) ON workspaces TO pingzo_keyresolver;

-- Resolves a topic key to its workspace without a context. Returns a row only
-- for a well-formed id, a matching hash, an unrevoked and unexpired key, and an
-- active workspace. $1 is key_id and $2 is key_hash.
CREATE FUNCTION public.resolve_topic_key(key_id text, key_hash bytea)
RETURNS TABLE (topic_id uuid, workspace_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT k.topic_id, k.workspace_id
    FROM public.topic_keys k
    JOIN public.workspaces w ON w.id = k.workspace_id
   WHERE $1 ~ '^pz_[a-z2-7]{8}$'
     AND k.id = $1
     AND k.key_hash = $2
     AND k.revoked_at IS NULL
     AND (k.expires_at IS NULL OR k.expires_at > now())
     AND w.status = 'active'
$$;

REVOKE EXECUTE ON FUNCTION public.resolve_topic_key(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_topic_key(text, bytea) TO pingzo_app;

-- Hand the function to pingzo_keyresolver. The new owner needs CREATE on the
-- schema for this one statement only, so it is granted and taken back here.
-- (The bootstrap makes pingzo_owner a member of pingzo_keyresolver.)
GRANT CREATE ON SCHEMA public TO pingzo_keyresolver;
ALTER FUNCTION public.resolve_topic_key(text, bytea) OWNER TO pingzo_keyresolver;
REVOKE CREATE ON SCHEMA public FROM pingzo_keyresolver;
