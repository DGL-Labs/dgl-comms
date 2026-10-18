-- C-1d A0: close the C-1c known gaps. Runs as pingzo_owner. Add-only.
-- Grants: this file adds no table grant for pingzo_app. It grants EXECUTE on
-- two functions to pingzo_app, and SELECT (owner_id) on workspaces plus USAGE
-- on the schema to pingzo_counter. EXECUTE on both functions is revoked from
-- PUBLIC. pingzo_counter holds CREATE on the schema only around the two OWNER
-- TO statements, and pingzo_counter is then revoked from pingzo_owner
-- (section 3).

-- 1. workspaces SELECT is scoped. A row is visible when its id is in the
-- context, or when the caller owns it (a workspace this transaction just made
-- is read back through the second clause).
DROP POLICY workspaces_select ON workspaces;
CREATE POLICY workspaces_select ON workspaces FOR SELECT
  USING (
    id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
    OR owner_id = nullif(current_setting('app.account_id', true), '')::uuid
  );

-- 2. The owner is tied to an owner row. The new owner_id must have the owner
-- role in members for this workspace. USING is unchanged.
ALTER POLICY workspaces_update ON workspaces
  WITH CHECK (
    id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])
    AND EXISTS (
      SELECT 1 FROM members m
       WHERE m.workspace_id = workspaces.id
         AND m.account_id = workspaces.owner_id
         AND m.role = 'owner'
    )
  );

-- 3. The two counts that cross workspaces. pingzo_counter (NOLOGIN and
-- BYPASSRLS, created by the bootstrap) owns only these two functions and can
-- read one column of one table.
GRANT USAGE ON SCHEMA public TO pingzo_counter;
GRANT SELECT (owner_id) ON workspaces TO pingzo_counter;

-- Workspaces owned by one account. $1 is account_id.
CREATE FUNCTION public.count_owned_workspaces(account_id uuid)
RETURNS integer
LANGUAGE sql STRICT STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT count(w.owner_id)::integer
    FROM public.workspaces w
   WHERE w.owner_id = $1
$$;

-- Workspaces in all. The create ceiling.
CREATE FUNCTION public.count_workspaces_total()
RETURNS integer
LANGUAGE sql STRICT STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT count(w.owner_id)::integer
    FROM public.workspaces w
$$;

REVOKE EXECUTE ON FUNCTION public.count_owned_workspaces(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.count_owned_workspaces(uuid) TO pingzo_app;
REVOKE EXECUTE ON FUNCTION public.count_workspaces_total() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.count_workspaces_total() TO pingzo_app;

-- Hand both functions to pingzo_counter, as 0003 did for resolve_topic_key.
-- (The bootstrap makes pingzo_owner a member of pingzo_counter.)
GRANT CREATE ON SCHEMA public TO pingzo_counter;
ALTER FUNCTION public.count_owned_workspaces(uuid) OWNER TO pingzo_counter;
ALTER FUNCTION public.count_workspaces_total() OWNER TO pingzo_counter;
REVOKE CREATE ON SCHEMA public FROM pingzo_counter;
-- Take the membership back, so that no login role can SET ROLE to the BYPASSRLS
-- role. If the revoke is refused (the grant was the superuser's), the
-- superuser step of the role bootstrap removes it and T-ROLE checks it.
DO $$
BEGIN
  REVOKE pingzo_counter FROM pingzo_owner;
EXCEPTION WHEN insufficient_privilege THEN
  NULL;
END
$$;
