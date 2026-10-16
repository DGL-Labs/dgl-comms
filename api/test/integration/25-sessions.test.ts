import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  bearer,
  makeApp,
  redeem,
  registerSecret,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

// Sessions: refresh rotation, reuse detection, logout, logout-all, the hook.
describe("sessions", () => {
  let t: TestApp;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
  });
  afterEach(() => t.close());

  const refresh = (refreshToken: string) => {
    registerSecret(refreshToken);
    return t.app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refresh_token: refreshToken },
    });
  };

  const logout = (accessToken: string, all = false) =>
    t.app.inject({
      method: "POST",
      url: all ? "/v1/auth/logout-all" : "/v1/auth/logout",
      headers: bearer(accessToken),
    });

  const probe = (accessToken: string) =>
    t.app.inject({
      method: "DELETE",
      url: "/v1/account",
      headers: bearer(accessToken),
    });

  it("rotates the refresh token and revokes the old session", async () => {
    const first = await signupAndVerify(t, uniqueEmail());
    const res = await refresh(first.refreshToken);
    expect(res.statusCode).toBe(200);
    const next = res.json<{ access_token: string; refresh_token: string }>();
    registerSecret(next.access_token);
    registerSecret(next.refresh_token);
    expect(next.refresh_token).not.toBe(first.refreshToken);
    expect(next.access_token).not.toBe(first.accessToken);

    const rows = await t.pool.query<{ revoked_at: Date | null }>(
      "SELECT revoked_at FROM sessions ORDER BY created_at, id",
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows.filter((r) => r.revoked_at !== null)).toHaveLength(1);
    expect(t.revoked).toHaveLength(1);

    // The old access token belongs to the revoked session.
    expect((await logout(first.accessToken)).statusCode).toBe(401);
    expect((await logout(next.access_token)).statusCode).toBe(204);
  });

  it("revokes every session when a revoked refresh token is reused", async () => {
    const email = uniqueEmail();
    const first = await signupAndVerify(t, email);
    const rotated = (await refresh(first.refreshToken)).json<{
      access_token: string;
      refresh_token: string;
    }>();
    registerSecret(rotated.access_token);
    registerSecret(rotated.refresh_token);
    t.revoked.length = 0;

    const reuse = await refresh(first.refreshToken);
    expect(reuse.statusCode).toBe(401);
    expect(t.revoked.flat()).toHaveLength(1);

    // The rotated session died too, and so does its refresh token.
    expect((await logout(rotated.access_token)).statusCode).toBe(401);
    expect((await refresh(rotated.refresh_token)).statusCode).toBe(401);
    const live = await t.pool.query(
      "SELECT 1 FROM sessions WHERE revoked_at IS NULL",
    );
    expect(live.rowCount).toBe(0);
  });

  it("rejects an unknown or expired refresh token", async () => {
    expect((await refresh("unknown-refresh-token")).statusCode).toBe(401);
    const first = await signupAndVerify(t, uniqueEmail());
    t.clock.advance(30 * 24 * 60 * 60 * 1000 + 1000);
    expect((await refresh(first.refreshToken)).statusCode).toBe(401);
  });

  it("refuses a refresh when the account is not active", async () => {
    const first = await signupAndVerify(t, uniqueEmail());
    await t.pool.query("UPDATE accounts SET status = 'suspended'");
    expect((await refresh(first.refreshToken)).statusCode).toBe(401);
    const live = await t.pool.query(
      "SELECT 1 FROM sessions WHERE revoked_at IS NULL",
    );
    expect(live.rowCount).toBe(1);
  });

  it("ends a refresh chain 90 days after it began", async () => {
    const day = 24 * 60 * 60 * 1000;
    let token = (await signupAndVerify(t, uniqueEmail())).refreshToken;
    // Each step is under the 30-day session life, so only the 90-day limit
    // can stop the chain: days 29, 58 and 87 work, day 116 does not.
    for (let i = 1; i <= 3; i++) {
      t.clock.advance(29 * day);
      const res = await refresh(token);
      expect(res.statusCode).toBe(200);
      token = res.json<{ refresh_token: string }>().refresh_token;
      registerSecret(token);
    }
    const chains = await t.pool.query(
      "SELECT DISTINCT chain_started_at FROM sessions",
    );
    expect(chains.rowCount).toBe(1);
    t.clock.advance(29 * day);
    expect((await refresh(token)).statusCode).toBe(401);
  });

  it("logout revokes this session only; logout-all revokes all", async () => {
    const email = uniqueEmail();
    const one = await signupAndVerify(t, email);
    // A second session through a login link.
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email },
    });
    const link = t.sender.lastTo(email);
    const two = (await redeem(t, (link as { token: string }).token)).json<{
      access_token: string;
    }>();
    registerSecret(two.access_token);

    t.revoked.length = 0;
    expect((await logout(one.accessToken)).statusCode).toBe(204);
    expect(t.revoked.flat()).toHaveLength(1);
    expect((await probe(one.accessToken)).statusCode).toBe(401);

    t.revoked.length = 0;
    expect((await logout(two.access_token, true)).statusCode).toBe(204);
    expect(t.revoked.flat()).toHaveLength(1);
    expect((await probe(two.access_token)).statusCode).toBe(401);
    const live = await t.pool.query(
      "SELECT 1 FROM sessions WHERE revoked_at IS NULL",
    );
    expect(live.rowCount).toBe(0);
  });
});
