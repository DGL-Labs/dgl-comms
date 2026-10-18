-- Role bootstrap for the test harness. Run as a superuser, connected to the
-- fresh test database. The app never runs this, and it holds no passwords: the
-- harness sets those from random values afterwards.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pingzo_owner') THEN
    CREATE ROLE pingzo_owner LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pingzo_app') THEN
    CREATE ROLE pingzo_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  -- Owns the key-resolving function only. It cannot log in, and it bypasses
  -- RLS so the function can look a key up before any context exists.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pingzo_keyresolver') THEN
    CREATE ROLE pingzo_keyresolver NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  -- Lets migration 0003 hand the function to pingzo_keyresolver
  -- (ALTER FUNCTION ... OWNER TO needs membership in the new owner). Only
  -- until then: a superuser step after the migrations runs
  -- REVOKE pingzo_keyresolver FROM pingzo_owner, because the grant below is
  -- the superuser's own and pingzo_owner cannot revoke it.
  GRANT pingzo_keyresolver TO pingzo_owner;
  -- Owns the two workspace-count functions only (migration 0004). NOLOGIN and
  -- BYPASSRLS, with SELECT on one column of workspaces. The same temporary
  -- membership for pingzo_owner, removed by the same superuser step.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pingzo_counter') THEN
    CREATE ROLE pingzo_counter NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  GRANT pingzo_counter TO pingzo_owner;
  -- The disk guard's role (migration 0007). Test bootstrap only: production
  -- provisioning is at C-1k. It can log in, but is not a superuser and does not
  -- bypass RLS, and it gets no privilege on any tenant table.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pingzo_maintainer') THEN
    CREATE ROLE pingzo_maintainer LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO pingzo_maintainer', current_database());
  -- The owner role owns the database, so it can create the citext extension
  -- (a trusted extension) and own everything in the public schema.
  EXECUTE format('ALTER DATABASE %I OWNER TO pingzo_owner', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO pingzo_app', current_database());
END
$$;
