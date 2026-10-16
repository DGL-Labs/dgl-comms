-- C-1b: accounts, sessions, magic links, login failures, sign-up events.
-- Runs as pingzo_owner. Add-only: later changes go in new numbered files.
-- The roles themselves are created by a bootstrap that only the test harness
-- (or an operator, as superuser) runs; the app never does.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  verified_at timestamptz NULL,
  auth_provider text NOT NULL DEFAULT 'magic_link',
  age_attested_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'active',
  deleted_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  refresh_hash bytea NOT NULL UNIQUE,
  -- r3 column. The devices table arrives at C-1f, so no foreign key yet.
  device_id uuid NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_account_id_idx ON sessions (account_id);

CREATE TABLE magic_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  purpose text NOT NULL CHECK (purpose IN ('verify', 'login')),
  expires_at timestamptz NOT NULL,
  used_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX magic_links_account_id_idx ON magic_links (account_id);

CREATE TABLE login_failures (
  id bigserial PRIMARY KEY,
  account_id uuid NULL,
  ip inet NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_account_idx ON login_failures (account_id, created_at);
CREATE INDEX login_failures_ip_idx ON login_failures (ip, created_at);

CREATE TABLE signup_events (
  id bigserial PRIMARY KEY,
  ip inet NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signup_events_ip_idx ON signup_events (ip, created_at);

-- pingzo_app owns nothing and can only read and write rows.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO pingzo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pingzo_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO pingzo_app;

-- Tables and sequences that later migrations add get the same grants.
ALTER DEFAULT PRIVILEGES FOR ROLE pingzo_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pingzo_app;
ALTER DEFAULT PRIVILEGES FOR ROLE pingzo_owner IN SCHEMA public
  GRANT USAGE ON SEQUENCES TO pingzo_app;
