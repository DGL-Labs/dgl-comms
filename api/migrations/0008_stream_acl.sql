-- C-1e B5: access changes tell the open streams. Runs as pingzo_owner.
-- Add-only. Grants: this file grants nothing. Each trigger function is
-- SECURITY INVOKER, so it runs with the rights of the role that changed the
-- row, and the only thing it calls is pg_notify. EXECUTE on each function is
-- revoked from PUBLIC (a trigger function cannot be called directly anyway).
--
-- Every function sends pg_notify('pingzo_acl', <ids only>) and nothing else: no
-- name, email or role. The notification is delivered when the transaction
-- commits. It is a hint: a stream that hears it re-checks access itself and
-- closes only if the check fails, so a forged notification closes nothing.
--
--   member:<workspace_id>:<account_id>   a member removed, or its role changed
--   session:<session_id>                 a session revoked
--   account:<account_id>                 an account deleted, or its status changed
--   topic:<topic_id>                     a topic deleted
--   workspace:<workspace_id>             a workspace suspended or deleted
--
-- The triggers fire on cascades and on changes made outside the app too.

CREATE FUNCTION public.pingzo_acl_member() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_notify(
    'pingzo_acl',
    'member:' || OLD.workspace_id::text || ':' || OLD.account_id::text
  );
  RETURN NULL;
END
$$;

CREATE FUNCTION public.pingzo_acl_session() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_notify('pingzo_acl', 'session:' || OLD.id::text);
  RETURN NULL;
END
$$;

CREATE FUNCTION public.pingzo_acl_account() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_notify('pingzo_acl', 'account:' || OLD.id::text);
  RETURN NULL;
END
$$;

CREATE FUNCTION public.pingzo_acl_topic() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_notify('pingzo_acl', 'topic:' || OLD.id::text);
  RETURN NULL;
END
$$;

CREATE FUNCTION public.pingzo_acl_workspace() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  PERFORM pg_notify('pingzo_acl', 'workspace:' || OLD.id::text);
  RETURN NULL;
END
$$;

REVOKE EXECUTE ON FUNCTION public.pingzo_acl_member() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.pingzo_acl_session() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.pingzo_acl_account() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.pingzo_acl_topic() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.pingzo_acl_workspace() FROM PUBLIC;

CREATE TRIGGER members_acl_delete AFTER DELETE ON members
  FOR EACH ROW EXECUTE FUNCTION public.pingzo_acl_member();
CREATE TRIGGER members_acl_role AFTER UPDATE OF role ON members
  FOR EACH ROW WHEN (OLD.role IS DISTINCT FROM NEW.role)
  EXECUTE FUNCTION public.pingzo_acl_member();

CREATE TRIGGER sessions_acl_revoked AFTER UPDATE OF revoked_at ON sessions
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION public.pingzo_acl_session();

CREATE TRIGGER accounts_acl_delete AFTER DELETE ON accounts
  FOR EACH ROW EXECUTE FUNCTION public.pingzo_acl_account();
CREATE TRIGGER accounts_acl_status AFTER UPDATE OF status ON accounts
  FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION public.pingzo_acl_account();

CREATE TRIGGER topics_acl_delete AFTER DELETE ON topics
  FOR EACH ROW EXECUTE FUNCTION public.pingzo_acl_topic();

CREATE TRIGGER workspaces_acl_status AFTER UPDATE OF status ON workspaces
  FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION public.pingzo_acl_workspace();
CREATE TRIGGER workspaces_acl_delete AFTER DELETE ON workspaces
  FOR EACH ROW EXECUTE FUNCTION public.pingzo_acl_workspace();
