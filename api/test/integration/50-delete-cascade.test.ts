import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deleteAccount } from "../../src/account.ts";
import { withTx } from "../../src/db.ts";
import {
  addMember,
  api,
  bearer,
  createWorkspace,
  makeApp,
  makeUser,
  redeem,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp, Tokens } from "./harness.ts";

// T-DELETE-CASCADE
describe("T-DELETE-CASCADE", () => {
  let t: TestApp;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
  });
  afterEach(() => t.close());

  // Rows in `table` that belong to the account (or all rows if no id).
  async function rows(table: string, column: string, id: string) {
    const res = await t.pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM ${table} WHERE ${column} = $1`,
      [id],
    );
    return res.rows[0]?.n;
  }

  async function accounts() {
    const res = await t.pool.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM accounts",
    );
    return res.rows[0]?.n;
  }

  const requestLogin = (email: string) =>
    t.app.inject({ method: "POST", url: "/v1/auth/login", payload: { email } });

  it("removes the account, sessions and links, and kills its tokens", async () => {
    const email = uniqueEmail();
    const one = await signupAndVerify(t, email);
    const id = one.accountId;
    // A second session, a pending login link, and a failure row inserted
    // directly (a replayed link now counts against the IP only).
    await requestLogin(email);
    const link = t.sender.lastTo(email) as { token: string };
    expect((await redeem(t, link.token)).statusCode).toBe(200);
    expect((await redeem(t, link.token)).statusCode).toBe(401);
    await requestLogin(email);
    expect(await rows("sessions", "account_id", id)).toBe(2);
    expect(await rows("magic_links", "account_id", id)).toBe(3);
    await t.pool.query(
      "INSERT INTO login_failures (account_id, ip) VALUES ($1, '198.51.100.9')",
      [id],
    );
    expect(await rows("login_failures", "account_id", id)).toBe(1);

    t.revoked.length = 0;
    const res = await t.app.inject({
      method: "DELETE",
      url: "/v1/account",
      headers: bearer(one.accessToken),
    });
    expect(res.statusCode).toBe(204);

    expect(await rows("accounts", "id", id)).toBe(0);
    expect(await rows("sessions", "account_id", id)).toBe(0);
    expect(await rows("magic_links", "account_id", id)).toBe(0);
    expect(await rows("login_failures", "account_id", id)).toBe(0);
    // The hook saw both live sessions.
    expect(t.revoked.flat()).toHaveLength(2);

    // Old tokens get 401.
    const again = await t.app.inject({
      method: "DELETE",
      url: "/v1/account",
      headers: bearer(one.accessToken),
    });
    expect(again.statusCode).toBe(401);
    const refreshed = await t.app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refresh_token: one.refreshToken },
    });
    expect(refreshed.statusCode).toBe(401);
  });

  it("leaves other accounts alone", async () => {
    const other = await signupAndVerify(t, uniqueEmail());
    const mine = await signupAndVerify(t, uniqueEmail());
    const res = await t.app.inject({
      method: "DELETE",
      url: "/v1/account",
      headers: bearer(mine.accessToken),
    });
    expect(res.statusCode).toBe(204);
    expect(await accounts()).toBe(1);
    const out = await t.app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: bearer(other.accessToken),
    });
    expect(out.statusCode).toBe(204);
  });

  it("deleteAccount rolls back with its transaction", async () => {
    const mine = await signupAndVerify(t, uniqueEmail());
    await expect(
      withTx(t.pool, async (tx) => {
        await deleteAccount(tx, mine.accountId);
        throw new Error("abort");
      }),
    ).rejects.toThrow("abort");
    expect(await accounts()).toBe(1);
  });

  describe("workspaces", () => {
    const del = (who: Tokens, confirm = false) =>
      t.app.inject({
        method: "DELETE",
        url: confirm ? "/v1/account?confirm=true" : "/v1/account",
        headers: bearer(who.accessToken),
      });

    const memberIds = async (who: Tokens, workspaceId: string) => {
      const res = await api(
        t,
        who,
        "GET",
        `/v1/workspaces/${workspaceId}/members`,
      );
      expect(res.statusCode).toBe(200);
      return res
        .json<{ members: { account_id: string }[] }>()
        .members.map((m) => m.account_id)
        .sort();
    };

    it("refuses while the account owns a workspace with other members", async () => {
      const owner = await makeUser(t);
      const other = await makeUser(t);
      const ws = await createWorkspace(t, owner);
      await addMember(t, owner, ws, other);
      t.revoked.length = 0;
      for (const confirm of [false, true]) {
        const res = await del(owner, confirm);
        expect(res.statusCode, `confirm ${confirm}`).toBe(409);
        expect(res.json()).toEqual({
          owned_workspaces: [{ id: ws, members: 2 }],
        });
      }
      // Nothing was deleted: the account, its sessions and the workspace.
      expect(await rows("accounts", "id", owner.accountId)).toBe(1);
      expect(await rows("workspaces", "id", ws)).toBe(1);
      expect(t.revoked.flat()).toHaveLength(0);
      expect(await memberIds(other, ws)).toEqual(
        [owner.accountId, other.accountId].sort(),
      );
      expect((await api(t, owner, "GET", "/v1/workspaces")).statusCode).toBe(
        200,
      );
    });

    it("proceeds after the owner transfers the workspace", async () => {
      const owner = await makeUser(t);
      const other = await makeUser(t);
      const ws = await createWorkspace(t, owner);
      await addMember(t, owner, ws, other);
      const moved = await api(
        t,
        owner,
        "POST",
        `/v1/workspaces/${ws}/transfer`,
        {
          accountId: other.accountId,
        },
      );
      expect(moved.statusCode).toBe(200);
      expect((await del(owner)).statusCode).toBe(204);
      expect(await rows("accounts", "id", owner.accountId)).toBe(0);
      // The workspace and the new owner's data are still there.
      expect(await rows("workspaces", "id", ws)).toBe(1);
      expect(await memberIds(other, ws)).toEqual([other.accountId]);
    });

    it("warns, then with confirm deletes sole-member workspaces and the account", async () => {
      const owner = await makeUser(t);
      const one = await createWorkspace(t, owner, "One");
      const two = await createWorkspace(t, owner, "Two");
      const warned = await del(owner);
      expect(warned.statusCode).toBe(409);
      expect(
        warned
          .json<{ owned_workspaces: { id: string; action: string }[] }>()
          .owned_workspaces.sort((x, y) => x.id.localeCompare(y.id)),
      ).toEqual(
        [
          { id: one, action: "delete" },
          { id: two, action: "delete" },
        ].sort((x, y) => x.id.localeCompare(y.id)),
      );
      expect(await rows("accounts", "id", owner.accountId)).toBe(1);
      expect(await rows("workspaces", "owner_id", owner.accountId)).toBe(2);

      expect((await del(owner, true)).statusCode).toBe(204);
      expect(await rows("accounts", "id", owner.accountId)).toBe(0);
      expect(await rows("workspaces", "owner_id", owner.accountId)).toBe(0);
      const memberships = await t.pool.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM members WHERE account_id = $1",
        [owner.accountId],
      );
      expect(memberships.rows[0]?.n).toBe(0);

      // One audit row for each workspace deleted, and one for the account.
      const audit = await t.pool.query<{ action: string; n: number }>(
        `SELECT action, count(*)::int AS n FROM audit_log
          WHERE actor_account_id = $1 AND action IN ('workspace.delete', 'account.delete')
          GROUP BY action`,
        [owner.accountId],
      );
      expect(
        Object.fromEntries(audit.rows.map((r) => [r.action, r.n])),
      ).toEqual({
        "workspace.delete": 2,
        "account.delete": 1,
      });
    });

    it("keeps a workspace that the account only joined, with the others' data", async () => {
      const owner = await makeUser(t);
      const joiner = await makeUser(t);
      const third = await makeUser(t);
      const shared = await createWorkspace(t, owner, "Shared");
      await addMember(t, owner, shared, joiner);
      await addMember(t, owner, shared, third);
      const solo = await createWorkspace(t, joiner, "Solo");

      // The joiner owns one workspace alone, so the first try only warns.
      expect((await del(joiner)).statusCode).toBe(409);
      expect((await del(joiner, true)).statusCode).toBe(204);

      expect(await rows("workspaces", "id", solo)).toBe(0);
      expect(await rows("workspaces", "id", shared)).toBe(1);
      expect(await memberIds(owner, shared)).toEqual(
        [owner.accountId, third.accountId].sort(),
      );
    });

    it("never transfers ownership by itself", async () => {
      const owner = await makeUser(t);
      const other = await makeUser(t);
      const ws = await createWorkspace(t, owner);
      await addMember(t, owner, ws, other, "admin");
      expect((await del(owner, true)).statusCode).toBe(409);
      const row = await t.pool.query<{ owner_id: string }>(
        "SELECT owner_id FROM workspaces WHERE id = $1",
        [ws],
      );
      expect(row.rows[0]?.owner_id).toBe(owner.accountId);
    });
  });
});
