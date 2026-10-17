import pg from "pg";
import { afterAll, describe, expect, inject, it } from "vitest";

// T-ROLE: runs first (files run in name order). The app role is not a
// superuser, cannot bypass RLS, and owns nothing.
describe("T-ROLE", () => {
  const pool = new pg.Pool({ connectionString: inject("dbUrl"), max: 2 });
  afterAll(() => pool.end());

  it("connects as pingzo_app", async () => {
    const res = await pool.query<{ u: string }>("SELECT current_user AS u");
    expect(res.rows[0]?.u).toBe("pingzo_app");
  });

  it("is neither superuser nor BYPASSRLS", async () => {
    const res = await pool.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
    );
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0]?.rolsuper).toBe(false);
    expect(res.rows[0]?.rolbypassrls).toBe(false);
  });

  it("owns no table, sequence or other relation", async () => {
    const res = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
        WHERE r.rolname = current_user`,
    );
    expect(res.rows[0]?.n).toBe(0);
  });

  it("owns no schema or database", async () => {
    const schemas = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_namespace s JOIN pg_roles r ON r.oid = s.nspowner
        WHERE r.rolname = current_user`,
    );
    expect(schemas.rows[0]?.n).toBe(0);
    const databases = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
        WHERE r.rolname = current_user`,
    );
    expect(databases.rows[0]?.n).toBe(0);
  });

  it("has no UPDATE on the event tables, but SELECT, INSERT, DELETE", async () => {
    const res = await pool.query<{ t: string; p: string; ok: boolean }>(
      `SELECT t, p, has_table_privilege(current_user, t, p) AS ok
         FROM unnest(ARRAY['signup_events', 'login_failures']) AS t,
              unnest(ARRAY['SELECT', 'INSERT', 'DELETE', 'UPDATE']) AS p`,
    );
    expect(res.rows).toHaveLength(8);
    for (const row of res.rows) {
      expect(row.ok, `${row.t} ${row.p}`).toBe(row.p !== "UPDATE");
    }
  });

  it("has append-only access to audit_log and read-only service_limits", async () => {
    const res = await pool.query<{ t: string; p: string; ok: boolean }>(
      `SELECT t, p, has_table_privilege(current_user, t, p) AS ok
         FROM unnest(ARRAY['audit_log', 'service_limits']) AS t,
              unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p`,
    );
    expect(res.rows).toHaveLength(8);
    for (const row of res.rows) {
      const allowed =
        row.p === "SELECT" || (row.t === "audit_log" && row.p === "INSERT");
      expect(row.ok, `${row.t} ${row.p}`).toBe(allowed);
    }
  });

  it("has no TRUNCATE on any table", async () => {
    const res = await pool.query<{ t: string; ok: boolean }>(
      `SELECT c.relname AS t, has_table_privilege(current_user, c.oid, 'TRUNCATE') AS ok
         FROM pg_class c
        WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'`,
    );
    expect(res.rows.length).toBeGreaterThan(5);
    for (const row of res.rows) {
      expect(row.ok, `${row.t} TRUNCATE`).toBe(false);
    }
  });

  describe("pingzo_counter", () => {
    it("cannot log in, bypasses RLS, and is not a superuser", async () => {
      const res = await pool.query<{
        rolcanlogin: boolean;
        rolbypassrls: boolean;
        rolsuper: boolean;
      }>(
        `SELECT rolcanlogin, rolbypassrls, rolsuper
           FROM pg_roles WHERE rolname = 'pingzo_counter'`,
      );
      expect(res.rows).toHaveLength(1);
      expect(res.rows[0]?.rolcanlogin).toBe(false);
      expect(res.rows[0]?.rolbypassrls).toBe(true);
      expect(res.rows[0]?.rolsuper).toBe(false);
    });

    it("owns exactly the two count functions", async () => {
      const owned = await pool.query<{ kind: string; name: string }>(
        `SELECT 'function' AS kind, p.proname AS name
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
          WHERE r.rolname = 'pingzo_counter'
         UNION ALL
         SELECT 'relation', c.relname
           FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
          WHERE r.rolname = 'pingzo_counter'
         UNION ALL
         SELECT 'schema', n.nspname
           FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
          WHERE r.rolname = 'pingzo_counter'
          ORDER BY 2`,
      );
      expect(owned.rows).toEqual([
        { kind: "function", name: "count_owned_workspaces" },
        { kind: "function", name: "count_workspaces_total" },
      ]);
      const objects = await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n
           FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid
          WHERE r.rolname = 'pingzo_counter' AND d.deptype = 'o'
            AND d.dbid = (SELECT oid FROM pg_database
                           WHERE datname = current_database())`,
      );
      expect(objects.rows[0]?.n).toBe(2);
    });

    it("has no member: pingzo_owner is not a member of it", async () => {
      const res = await pool.query<{ member: string }>(
        `SELECT m.rolname AS member
           FROM pg_auth_members am
           JOIN pg_roles r ON r.oid = am.roleid
           JOIN pg_roles m ON m.oid = am.member
          WHERE r.rolname = 'pingzo_counter'`,
      );
      expect(res.rows).toEqual([]);
    });

    it("has only SELECT on workspaces.owner_id", async () => {
      const res = await pool.query<{ ok: boolean }>(
        `SELECT has_column_privilege('pingzo_counter', 'workspaces', 'owner_id', 'SELECT')
                AND NOT has_column_privilege('pingzo_counter', 'workspaces', 'name', 'SELECT')
                AND NOT has_column_privilege('pingzo_counter', 'workspaces', 'id', 'SELECT')
                AND NOT has_table_privilege('pingzo_counter', 'workspaces', 'INSERT')
                AND NOT has_table_privilege('pingzo_counter', 'workspaces', 'UPDATE')
                AND NOT has_table_privilege('pingzo_counter', 'workspaces', 'DELETE')
                AND NOT has_table_privilege('pingzo_counter', 'members', 'SELECT')
                AND NOT has_table_privilege('pingzo_counter', 'accounts', 'SELECT')
                AND NOT has_schema_privilege('pingzo_counter', 'public', 'CREATE')
                AS ok`,
      );
      expect(res.rows[0]?.ok).toBe(true);
    });
  });

  describe("pingzo_keyresolver", () => {
    it("cannot log in, bypasses RLS, and is not a superuser", async () => {
      const res = await pool.query<{
        rolcanlogin: boolean;
        rolbypassrls: boolean;
        rolsuper: boolean;
      }>(
        `SELECT rolcanlogin, rolbypassrls, rolsuper
           FROM pg_roles WHERE rolname = 'pingzo_keyresolver'`,
      );
      expect(res.rows).toHaveLength(1);
      expect(res.rows[0]?.rolcanlogin).toBe(false);
      expect(res.rows[0]?.rolbypassrls).toBe(true);
      expect(res.rows[0]?.rolsuper).toBe(false);
    });

    it("owns exactly one object: the function", async () => {
      const owned = await pool.query<{ kind: string; name: string }>(
        `SELECT 'function' AS kind, p.proname AS name
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
          WHERE r.rolname = 'pingzo_keyresolver'
         UNION ALL
         SELECT 'relation', c.relname
           FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
          WHERE r.rolname = 'pingzo_keyresolver'
         UNION ALL
         SELECT 'schema', n.nspname
           FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
          WHERE r.rolname = 'pingzo_keyresolver'`,
      );
      expect(owned.rows).toEqual([
        { kind: "function", name: "resolve_topic_key" },
      ]);
      const objects = await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n
           FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid
          WHERE r.rolname = 'pingzo_keyresolver' AND d.deptype = 'o'
            AND d.dbid = (SELECT oid FROM pg_database
                           WHERE datname = current_database())`,
      );
      expect(objects.rows[0]?.n).toBe(1);
    });

    it("has no member: neither pingzo_app nor pingzo_owner can become it", async () => {
      const res = await pool.query<{ member: string }>(
        `SELECT m.rolname AS member
           FROM pg_auth_members am
           JOIN pg_roles r ON r.oid = am.roleid
           JOIN pg_roles m ON m.oid = am.member
          WHERE r.rolname = 'pingzo_keyresolver'`,
      );
      expect(res.rows).toEqual([]);
    });

    it("has only the grants it needs", async () => {
      const res = await pool.query<{ ok: boolean }>(
        `SELECT has_table_privilege('pingzo_keyresolver', 'topic_keys', 'SELECT')
                AND NOT has_table_privilege('pingzo_keyresolver', 'topic_keys', 'INSERT')
                AND NOT has_table_privilege('pingzo_keyresolver', 'topic_keys', 'UPDATE')
                AND NOT has_table_privilege('pingzo_keyresolver', 'topic_keys', 'DELETE')
                AND has_column_privilege('pingzo_keyresolver', 'workspaces', 'status', 'SELECT')
                AND NOT has_column_privilege('pingzo_keyresolver', 'workspaces', 'name', 'SELECT')
                AND NOT has_table_privilege('pingzo_keyresolver', 'members', 'SELECT')
                AND NOT has_table_privilege('pingzo_keyresolver', 'accounts', 'SELECT')
                AND NOT has_schema_privilege('pingzo_keyresolver', 'public', 'CREATE')
                AS ok`,
      );
      expect(res.rows[0]?.ok).toBe(true);
    });
  });

  it("cannot create tables", async () => {
    await expect(
      pool.query("CREATE TABLE t_role_probe (a int)"),
    ).rejects.toThrow();
  });
});
