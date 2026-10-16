import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deleteAccount } from "../../src/account.ts";
import { withTx } from "../../src/db.ts";
import {
  bearer,
  makeApp,
  redeem,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

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
});
