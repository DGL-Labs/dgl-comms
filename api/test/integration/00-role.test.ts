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

  it("cannot create tables", async () => {
    await expect(
      pool.query("CREATE TABLE t_role_probe (a int)"),
    ).rejects.toThrow();
  });
});
