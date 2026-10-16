import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withContext, withKeyContext } from "../../src/db.ts";
import { hashToken } from "../../src/tokens.ts";
import {
  api,
  appWithHooks,
  createWorkspace,
  inContext,
  makeApp,
  makeUser,
  uniqueEmail,
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

    it("a route with its permission check skipped still gets no B rows", async () => {
      const broken = await appWithHooks(t, { skipPermissionChecks: true });
      try {
        const headers = { authorization: `Bearer ${a.accessToken}` };
        const members = await broken.inject({
          method: "GET",
          url: `/v1/workspaces/${wsB}/members`,
          headers,
        });
        expect(members.statusCode).toBe(200);
        expect(members.json<{ members: unknown[] }>().members).toEqual([]);

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
      } finally {
        await broken.close();
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
      await t.pool.query(
        "UPDATE workspaces SET status = 'suspended' WHERE id = $1",
        [wsSuspended],
      );
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
