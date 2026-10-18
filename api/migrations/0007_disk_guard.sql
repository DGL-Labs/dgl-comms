-- C-1d A6: disk guard, stage (a). Runs as pingzo_owner. Add-only.
-- Grants: service_alerts and its sequence are revoked from pingzo_app (the
-- default privileges from 0001 would hand it DML) and granted to
-- pingzo_maintainer only. pingzo_maintainer also gets USAGE on the schema,
-- SELECT and a column UPDATE on service_limits, and INSERT on audit_log with
-- USAGE on audit_log_id_seq. It gets nothing on any tenant table. pingzo_app
-- gets no new privilege. CONNECT on the database is in the role bootstrap.
-- pingzo_maintainer is created by the test bootstrap only; production
-- provisioning is at C-1k (docs/DB-ROLES.md).

-- Alerts raised by the disk guard. detail holds numbers only. Delivery is C-1h,
-- which sets delivered_at.
CREATE TABLE service_alerts (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL,
  level text NOT NULL CHECK (level IN ('warning', 'critical')),
  detail text NOT NULL,
  delivered_at timestamptz NULL
);

-- The missing-status alert is raised once: a second undelivered one is refused.
-- The guard has no SELECT on this table, so it relies on this index.
CREATE UNIQUE INDEX service_alerts_status_missing_once_idx
  ON service_alerts (kind)
  WHERE kind = 'disk_status_missing' AND delivered_at IS NULL;

REVOKE ALL ON service_alerts FROM pingzo_app;
REVOKE ALL ON SEQUENCE service_alerts_id_seq FROM pingzo_app;

GRANT USAGE ON SCHEMA public TO pingzo_maintainer;
GRANT SELECT ON service_limits TO pingzo_maintainer;
GRANT UPDATE (signup_paused, publish_paused_non_internal)
  ON service_limits TO pingzo_maintainer;
GRANT INSERT ON service_alerts TO pingzo_maintainer;
GRANT USAGE ON SEQUENCE service_alerts_id_seq TO pingzo_maintainer;
GRANT INSERT ON audit_log TO pingzo_maintainer;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO pingzo_maintainer;

-- Row-level security on audit_log (G5 S2). The invite caps count audit_log
-- rows, so a maintainer able to insert any row could forge history or use up
-- a cap. pingzo_app keeps exactly what its grants give it (SELECT and INSERT
-- on every row). pingzo_maintainer may insert only a flag-clear row with no
-- workspace. RLS is not forced, so pingzo_owner is unaffected.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_log_app_select ON audit_log FOR SELECT TO pingzo_app
  USING (true);
CREATE POLICY audit_log_app_insert ON audit_log FOR INSERT TO pingzo_app
  WITH CHECK (true);
CREATE POLICY audit_log_maintainer_insert ON audit_log FOR INSERT
  TO pingzo_maintainer
  WITH CHECK (
    action = 'service.flag_clear'
    AND workspace_id IS NULL
    AND target IN ('signup_paused', 'publish_paused_non_internal')
  );
