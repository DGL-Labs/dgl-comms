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
  -- The owner role owns the database, so it can create the citext extension
  -- (a trusted extension) and own everything in the public schema.
  EXECUTE format('ALTER DATABASE %I OWNER TO pingzo_owner', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO pingzo_app', current_database());
END
$$;
