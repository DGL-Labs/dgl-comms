import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  withContext,
  withKeyContext,
  withPathContext,
} from "../../src/db.ts";
import { hashToken } from "../../src/tokens.ts";
import {
  api,
  appWithHooks,
  createWorkspace,
  inContext,
  makeApp,
  makeUser,
  ownerPool,
  uniqueEmail,
  withAllWorkspaces,
} from "./harness.ts";
import type { TestApp, User } from "./harness.ts";

const KEY_A = "pz_aaaaaaaa";
const KEY_B = "pz_bbbbbbbb";
const SECRET_A = "test-key-secret-a";
const SECRET_B = "test-key-secret-b";

// T-RLS and T-KEYCTX: row-level security checked directly, as pingzo_app.
describe("T-RLS and T-KEYCTX", () => {
  let t: TestApp;
  let a: User;
  let b: User;
  let wsA: string;
  let wsB: string;
  let wsSuspended: string;

  async function seedKey(
    owner: User,
    workspaceId: string,
    id: string,
    secret: string,
    extra: { expiresAt?: Date; revokedAt?: Date } = {},
  ): Promise<string> {
    const topicId = randomUUID();
    await withContext(t.pool, { accountId: owner.accountId }, (tx) =>
      tx.query(
        `INSERT INTO topic_keys (id, key_hash, topic_id, workspace_id, expires_at, revoked_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          id,
          hashToken(secret),
          topicId,
          workspaceId,
          extra.expiresAt ?? null,
          extra.revokedAt ?? null,
        ],
      ),
    );
    return topicId;
  }

  beforeAll(async () => {
    t = await makeApp({ allowlistOn: false });
    a = await makeUser(t);
    b = await makeUser(t);
    wsA = await createWorkspace(t, a, "Workspace A");
    wsB = await createWorkspace(t, b, "Workspace B");
    wsSuspended = await createWorkspace(t, a, "Workspace S");
    // An invitation in each workspace.
    for (const [who, ws] of [
      [a, wsA],
      [b, wsB],
    ] as const) {
      const res = await api(
        t,
        who,
        "POST",
        `/v1/workspaces/${ws}/invitations`,
        {
          email: uniqueEmail(),
          role: "member",
        },
      );
      expect(res.statusCode).toBe(201);
    }
  });
  afterAll(() => t.close());

  describe("T-RLS", () => {
    const tables = ["members", "invitations", "topic_keys"] as const;

    beforeAll(async () => {
      await seedKey(a, wsA, KEY_A, SECRET_A);
      await seedKey(b, wsB, KEY_B, SECRET_B);
    });

    it("context A: sees its own rows and none of B", async () => {
      for (const table of tables) {
        const res = await inContext(t.pool, { workspaceIds: [wsA] }, (c) =>
          c.query<{ mine: number; theirs: number }>(
            `SELECT count(*) FILTER (WHERE workspace_id = $1)::int AS mine,
                      count(*) FILTER (WHERE workspace_id = $2)::int AS theirs
                 FROM ${table}`,
            [wsA, wsB],
          ),
        );
        expect(res.rows[0]?.mine, `${table} positive control`).toBeGreaterThan(
          0,
        );
        expect(res.rows[0]?.theirs, table).toBe(0);
      }
    });

    it("a missing or empty context gives zero rows", async () => {
      for (const table of tables) {
        const none = await inContext(t.pool, {}, (c) =>
          c.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`),
        );
        expect(none.rows[0]?.n, `${table} missing`).toBe(0);
        for (const raw of ["", "{}"]) {
          const empty = await inContext(t.pool, { raw }, (c) =>
            c.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`),
          );
          expect(empty.rows[0]?.n, `${table} '${raw}'`).toBe(0);
        }
      }
    });

    it("members also shows the caller's own rows, and only those", async () => {
      const res = await inContext(t.pool, { accountId: a.accountId }, (c) =>
        c.query<{ mine: number; others: number }>(
          `SELECT count(*) FILTER (WHERE account_id = $1)::int AS mine,
                  count(*) FILTER (WHERE account_id <> $1)::int AS others
             FROM members`,
          [a.accountId],
        ),
      );
      // A owns two workspaces and nobody else is in them.
      expect(res.rows[0]?.mine).toBe(2);
      expect(res.rows[0]?.others).toBe(0);
    });

    it("WITH CHECK refuses inserting a B row under context A", async () => {
      const inserts: Record<string, [string, unknown[]]> = {
        members: [
          `INSERT INTO members (workspace_id, account_id, role)
           VALUES ($1, $2, 'member')`,
          [wsB, a.accountId],
        ],
        invitations: [
          `INSERT INTO invitations (workspace_id, invited_by, email, role, token_hash, expires_at)
           VALUES ($1, $2, 'x@example.test', 'member', $3, now() + interval '1 day')`,
          [wsB, a.accountId, hashToken("rls-insert-probe")],
        ],
        topic_keys: [
          `INSERT INTO topic_keys (id, key_hash, topic_id, workspace_id)
           VALUES ('pz_cccccccc', $1, $2, $3)`,
          [hashToken("rls-insert-probe"), randomUUID(), wsB],
        ],
      };
      for (const [table, [sql, values]] of Object.entries(inserts)) {
        await expect(
          inContext(
            t.pool,
            { accountId: a.accountId, workspaceIds: [wsA] },
            (c) => c.query(sql, values),
          ),
          table,
        ).rejects.toThrow(/row-level security/);
      }
    });

    it("WITH CHECK refuses moving an A row to B", async () => {
      for (const table of tables) {
        await expect(
          inContext(
            t.pool,
            { accountId: a.accountId, workspaceIds: [wsA] },
            (c) =>
              c.query(
                `UPDATE ${table} SET workspace_id = $2 WHERE workspace_id = $1`,
                [wsA, wsB],
              ),
          ),
          table,
        ).rejects.toThrow(/row-level security/);
      }
    });

    it("UPDATE and DELETE do not reach B rows", async () => {
      for (const table of tables) {
        const res = await inContext(t.pool, { workspaceIds: [wsA] }, (c) =>
          c.query(`DELETE FROM ${table} WHERE workspace_id = $1`, [wsB]),
        );
        expect(res.rowCount, table).toBe(0);
      }
    });

    it("workspaces: UPDATE and DELETE on B affect 0 rows under context A", async () => {
      await inContext(
        t.pool,
        { accountId: a.accountId, workspaceIds: [wsA] },
        async (c) => {
          const renamed = await c.query(
            "UPDATE workspaces SET name = 'x' WHERE id = $1",
            [wsB],
          );
          expect(renamed.rowCount).toBe(0);
          const moved = await c.query(
            "UPDATE workspaces SET owner_id = $2 WHERE id = $1",
            [wsB, a.accountId],
          );
          expect(moved.rowCount).toBe(0);
          const deleted = await c.query(
            "DELETE FROM workspaces WHERE id = $1",
            [wsB],
          );
          expect(deleted.rowCount).toBe(0);
          // Positive control: A's own workspace can be renamed.
          const own = await c.query(
            "UPDATE workspaces SET name = 'Workspace A' WHERE id = $1",
            [wsA],
          );
          expect(own.rowCount).toBe(1);
        },
      );
    });

    it("workspaces: INSERT for another owner is refused, and status is not updatable", async () => {
      await expect(
        inContext(t.pool, { accountId: a.accountId }, (c) =>
          c.query(
            "INSERT INTO workspaces (owner_id, name, kind) VALUES ($1, 'x', 'team')",
            [b.accountId],
          ),
        ),
      ).rejects.toThrow(/row-level security/);
      await expect(
        inContext(
          t.pool,
          { accountId: a.accountId, workspaceIds: [wsA] },
          (c) =>
            c.query(
              "UPDATE workspaces SET status = 'suspended' WHERE id = $1",
              [wsA],
            ),
        ),
      ).rejects.toThrow(/permission denied/);
    });

    it("a route with its permission check skipped still gets no B rows", async () => {
      const broken = await appWithHooks(t, { skipPermissionChecks: true });
      try {
        const headers = { authorization: `Bearer ${a.accessToken}` };
        // Everything of B, read as B's own context.
        const snapshot = () =>
          inContext(t.pool, { workspaceIds: [wsB] }, async (c) => {
            const one = async (sql: string) => (await c.query(sql, [wsB])).rows;
            return {
              workspace: await one(
                "SELECT id, owner_id, name, kind, status FROM workspaces WHERE id = $1",
              ),
              members: await one(
                "SELECT account_id, role FROM members WHERE workspace_id = $1 ORDER BY account_id",
              ),
              invitations: await one(
                "SELECT id, email, role, used_at FROM invitations WHERE workspace_id = $1 ORDER BY id",
              ),
              limits: await one(
                "SELECT * FROM workspace_limits WHERE workspace_id = $1",
              ),
              keys: await one(
                "SELECT id, topic_id, revoked_at FROM topic_keys WHERE workspace_id = $1 ORDER BY id",
              ),
            };
          });
        const before = await snapshot();
        expect(before.workspace).toHaveLength(1);
        expect(before.keys.length).toBeGreaterThan(0);

        const renamed = await broken.inject({
          method: "PATCH",
          url: `/v1/workspaces/${wsB}`,
          headers,
          payload: { name: "Taken over" },
        });
        expect(renamed.statusCode).toBe(404);
        const transferred = await broken.inject({
          method: "POST",
          url: `/v1/workspaces/${wsB}/transfer`,
          headers,
          payload: { accountId: b.accountId },
        });
        expect(transferred.statusCode).toBe(404);
        const deleted = await broken.inject({
          method: "DELETE",
          url: `/v1/workspaces/${wsB}`,
          headers,
        });
        expect(deleted.statusCode).toBe(404);
        expect(await snapshot()).toEqual(before);

        const members = await broken.inject({
          method: "GET",
          url: `/v1/workspaces/${wsB}/members`,
          headers,
        });
        expect(members.statusCode).toBe(200);
        expect(members.json<{ members: unknown[] }>().members).toEqual([]);

        // SELECT on workspaces is scoped (C-1d A0): a broken check no longer
        // reads B's own row.
        const read = await broken.inject({
          method: "GET",
          url: `/v1/workspaces/${wsB}`,
          headers,
        });
        expect(read.statusCode).toBe(404);

        const removed = await broken.inject({
          method: "DELETE",
          url: `/v1/workspaces/${wsB}/members/${b.accountId}`,
          headers,
        });
        expect(removed.statusCode).toBe(404);

        const invited = await broken.inject({
          method: "POST",
          url: `/v1/workspaces/${wsB}/invitations`,
          headers,
          payload: { email: uniqueEmail(), role: "admin" },
        });
        expect(invited.statusCode).toBe(500);

        // B is untouched: its owner is still a member and it has one
        // invitation only.
        const after = await inContext(
          t.pool,
          { workspaceIds: [wsB] },
          async (c) => {
            const m = await c.query<{ n: number }>(
              "SELECT count(*)::int AS n FROM members WHERE workspace_id = $1",
              [wsB],
            );
            const i = await c.query<{ n: number }>(
              "SELECT count(*)::int AS n FROM invitations WHERE workspace_id = $1",
              [wsB],
            );
            return { members: m.rows[0]?.n, invitations: i.rows[0]?.n };
          },
        );
        expect(after).toEqual({ members: 1, invitations: 1 });
        expect(await snapshot()).toEqual(before);
      } finally {
        await broken.close();
      }
    });
  });

  describe("A0: path context, scoped workspaces, count functions", () => {
    it("workspaces SELECT shows the context's workspaces and the caller's own", async () => {
      const ids = (settings: {
        accountId?: string;
        workspaceIds?: string[];
      }) =>
        inContext(t.pool, settings, async (c) =>
          (await c.query<{ id: string }>("SELECT id FROM workspaces")).rows
            .map((r) => r.id)
            .sort(),
        );
      expect(await ids({})).toEqual([]);
      expect(await ids({ workspaceIds: [wsA] })).toEqual([wsA]);
      expect(await ids({ accountId: b.accountId })).toEqual([wsB]);
      expect(await ids({ accountId: a.accountId })).toEqual(
        [wsA, wsSuspended].sort(),
      );
    });

    it("withPathContext holds only the path workspace for a member", async () => {
      const seen = await withPathContext(
        t.pool,
        { accountId: a.accountId },
        wsA,
        async (tx) => {
          const setting = await tx.query<{ v: string }>(
            "SELECT current_setting('app.workspace_ids', true) AS v",
          );
          const workspaces = await tx.query<{ id: string }>(
            "SELECT id FROM workspaces WHERE id = ANY ($1::uuid[])",
            [[wsA, wsSuspended]],
          );
          return {
            setting: setting.rows[0]?.v,
            ids: workspaces.rows.map((r) => r.id),
          };
        },
      );
      // A is a member of wsA and wsSuspended and owns both: the setting holds
      // only wsA, and so does what the context shows of members. (workspaces
      // also shows the caller's own rows, by owner.)
      expect(seen.setting).toBe(`{${wsA}}`);
      expect(seen.ids.sort()).toEqual([wsA, wsSuspended].sort());
    });

    it("withPathContext gives a non-member an empty context and never adds", async () => {
      const seen = await withPathContext(
        t.pool,
        { accountId: a.accountId },
        wsB,
        async (tx) => {
          const setting = await tx.query<{ v: string }>(
            "SELECT current_setting('app.workspace_ids', true) AS v",
          );
          const workspaces = await tx.query(
            "SELECT id FROM workspaces WHERE id = $1",
            [wsB],
          );
          const members = await tx.query(
            "SELECT 1 FROM members WHERE workspace_id = $1",
            [wsB],
          );
          return {
            setting: setting.rows[0]?.v,
            workspaces: workspaces.rowCount,
            members: members.rowCount,
          };
        },
      );
      expect(seen).toEqual({ setting: "{}", workspaces: 0, members: 0 });
    });

    it("an owner change to an account without the owner row is refused", async () => {
      // B is not a member of wsA, so it has no owner row there, even with the
      // context set to wsA.
      await expect(
        inContext(
          t.pool,
          { accountId: a.accountId, workspaceIds: [wsA] },
          (c) =>
            c.query("UPDATE workspaces SET owner_id = $2 WHERE id = $1", [
              wsA,
              b.accountId,
            ]),
        ),
      ).rejects.toThrow(/row-level security/);
    });

    it("the count functions count owners and are closed to PUBLIC", async () => {
      const res = await t.pool.query<{
        owned: number;
        total: number;
        none: number | null;
      }>(
        `SELECT count_owned_workspaces($1) AS owned,
                count_workspaces_total() AS total,
                count_owned_workspaces(NULL) AS none`,
        [a.accountId],
      );
      expect(res.rows[0]).toEqual({ owned: 2, total: 3, none: null });
      const priv = await t.pool.query<{
        owned_pub: boolean;
        total_pub: boolean;
        owned_app: boolean;
        total_app: boolean;
      }>(
        `SELECT has_function_privilege('public', 'count_owned_workspaces(uuid)', 'EXECUTE') AS owned_pub,
                has_function_privilege('public', 'count_workspaces_total()', 'EXECUTE') AS total_pub,
                has_function_privilege('pingzo_app', 'count_owned_workspaces(uuid)', 'EXECUTE') AS owned_app,
                has_function_privilege('pingzo_app', 'count_workspaces_total()', 'EXECUTE') AS total_app`,
      );
      expect(priv.rows[0]).toEqual({
        owned_pub: false,
        total_pub: false,
        owned_app: true,
        total_app: true,
      });
    });

    it("the count functions are STRICT STABLE SECURITY DEFINER with a fixed search_path", async () => {
      const res = await t.pool.query<{
        proname: string;
        prosecdef: boolean;
        proisstrict: boolean;
        provolatile: string;
        proconfig: string[] | null;
        owner: string;
      }>(
        `SELECT p.proname, p.prosecdef, p.proisstrict, p.provolatile, p.proconfig,
                r.rolname AS owner
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
          WHERE p.proname IN ('count_owned_workspaces', 'count_workspaces_total')
            AND p.pronamespace = 'public'::regnamespace
          ORDER BY p.proname`,
      );
      expect(res.rows).toHaveLength(2);
      for (const row of res.rows) {
        expect(row.prosecdef, row.proname).toBe(true);
        expect(row.proisstrict, row.proname).toBe(true);
        expect(row.provolatile, row.proname).toBe("s");
        expect(row.proconfig, row.proname).toContain(
          "search_path=pg_catalog, pg_temp",
        );
        expect(row.owner, row.proname).toBe("pingzo_counter");
      }
    });
  });

  describe("T-KEYCTX", () => {
    const resolve = (id: string, secret: string) =>
      t.pool.query<{ topic_id: string; workspace_id: string }>(
        "SELECT * FROM resolve_topic_key($1, $2)",
        [id, hashToken(secret)],
      );

    it("resolves a valid key", async () => {
      const topicId = await seedKey(a, wsA, "pz_dddddddd", "valid-secret");
      const res = await resolve("pz_dddddddd", "valid-secret");
      expect(res.rows).toEqual([{ topic_id: topicId, workspace_id: wsA }]);
    });

    it("returns no row for a wrong hash", async () => {
      expect((await resolve(KEY_A, "not-the-secret")).rows).toHaveLength(0);
    });

    it("returns no row for an expired key", async () => {
      await seedKey(a, wsA, "pz_eeeeeeee", "expired-secret", {
        expiresAt: new Date(Date.now() - 60_000),
      });
      expect(
        (await resolve("pz_eeeeeeee", "expired-secret")).rows,
      ).toHaveLength(0);
    });

    it("resolves a key that has not yet expired", async () => {
      await seedKey(a, wsA, "pz_ffffffff", "future-secret", {
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      expect((await resolve("pz_ffffffff", "future-secret")).rows).toHaveLength(
        1,
      );
    });

    it("returns no row for a revoked key", async () => {
      await seedKey(a, wsA, "pz_gggggggg", "revoked-secret", {
        revokedAt: new Date(Date.now() - 60_000),
      });
      expect(
        (await resolve("pz_gggggggg", "revoked-secret")).rows,
      ).toHaveLength(0);
    });

    it("returns no row for a key of a suspended workspace", async () => {
      await seedKey(a, wsSuspended, "pz_hhhhhhhh", "suspended-secret");
      expect(
        (await resolve("pz_hhhhhhhh", "suspended-secret")).rows,
      ).toHaveLength(1);
      // The app role cannot change status, so the owner role does it.
      const db = ownerPool();
      try {
        await withAllWorkspaces(db, (c) =>
          c.query("UPDATE workspaces SET status = 'suspended' WHERE id = $1", [
            wsSuspended,
          ]),
        );
      } finally {
        await db.end();
      }
      expect(
        (await resolve("pz_hhhhhhhh", "suspended-secret")).rows,
      ).toHaveLength(0);
    });

    it("returns no row for a malformed id", async () => {
      for (const id of [
        "PZ_AAAAAAAA",
        "pz_aaaaaaa",
        "pz_aaaaaaaaa",
        "pz_aaaaaaa1",
        "xx_aaaaaaaa",
        "pz_aaaaaaaa\n",
        "",
      ]) {
        expect(
          (await resolve(id, SECRET_A)).rows,
          JSON.stringify(id),
        ).toHaveLength(0);
      }
    });

    it("a direct SELECT on topic_keys with no context returns 0 rows", async () => {
      const res = await t.pool.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM topic_keys",
      );
      expect(res.rows[0]?.n).toBe(0);
    });

    it("the function is not executable by PUBLIC, but is by pingzo_app", async () => {
      const res = await t.pool.query<{ pub: boolean; app: boolean }>(
        `SELECT has_function_privilege('public', 'resolve_topic_key(text,bytea)', 'EXECUTE') AS pub,
                has_function_privilege('pingzo_app', 'resolve_topic_key(text,bytea)', 'EXECUTE') AS app`,
      );
      expect(res.rows[0]).toEqual({ pub: false, app: true });
    });

    it("resolve_topic_key is SECURITY DEFINER with a fixed search_path and the right owner", async () => {
      const res = await t.pool.query<{
        prosecdef: boolean;
        proconfig: string[] | null;
        owner: string;
      }>(
        `SELECT p.prosecdef, p.proconfig, r.rolname AS owner
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
          WHERE p.proname = 'resolve_topic_key'
            AND p.pronamespace = 'public'::regnamespace`,
      );
      expect(res.rows).toHaveLength(1);
      expect(res.rows[0]?.prosecdef).toBe(true);
      expect(res.rows[0]?.proconfig).toContain(
        "search_path=pg_catalog, pg_temp",
      );
      expect(res.rows[0]?.owner).toBe("pingzo_keyresolver");
    });

    it("withKeyContext sees exactly the key's workspace", async () => {
      const seen = await withKeyContext(
        t.pool,
        KEY_A,
        hashToken(SECRET_A),
        async (tx, key) => {
          const keys = await tx.query<{ workspace_id: string }>(
            "SELECT DISTINCT workspace_id FROM topic_keys",
          );
          const members = await tx.query<{ workspace_id: string }>(
            "SELECT DISTINCT workspace_id FROM members",
          );
          const invitations = await tx.query<{ workspace_id: string }>(
            "SELECT DISTINCT workspace_id FROM invitations",
          );
          return {
            key,
            keys: keys.rows.map((r) => r.workspace_id),
            members: members.rows.map((r) => r.workspace_id),
            invitations: invitations.rows.map((r) => r.workspace_id),
          };
        },
      );
      expect(seen).not.toBeNull();
      expect(seen?.key.workspaceId).toBe(wsA);
      expect(seen?.keys).toEqual([wsA]);
      expect(seen?.members).toEqual([wsA]);
      expect(seen?.invitations).toEqual([wsA]);
    });

    it("withKeyContext does not run fn for a key that does not resolve", async () => {
      let ran = false;
      const seen = await withKeyContext(
        t.pool,
        KEY_A,
        hashToken("wrong"),
        async () => {
          ran = true;
          return "ran";
        },
      );
      expect(seen).toBeNull();
      expect(ran).toBe(false);
    });

    it("the context ends with the transaction", async () => {
      await withKeyContext(t.pool, KEY_A, hashToken(SECRET_A), async () => 1);
      const res = await t.pool.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM topic_keys",
      );
      expect(res.rows[0]?.n).toBe(0);
    });
  });
});
