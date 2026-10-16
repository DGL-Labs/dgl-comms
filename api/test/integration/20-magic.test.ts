import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashToken } from "../../src/tokens.ts";
import {
  makeApp,
  redeem,
  registerSecret,
  signup,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

// T-MAGIC
describe("T-MAGIC", () => {
  let t: TestApp;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
  });
  afterEach(() => t.close());

  async function newLink(): Promise<{ email: string; token: string }> {
    const email = uniqueEmail();
    expect((await signup(t, email)).statusCode).toBe(202);
    const message = t.sender.lastTo(email);
    expect(message?.kind).toBe("verify");
    return { email, token: (message as { token: string }).token };
  }

  it("works once", async () => {
    const { email, token } = await newLink();
    const first = await redeem(t, token);
    expect(first.statusCode).toBe(200);
    const body = first.json<Record<string, unknown>>();
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(900);
    const account = await t.pool.query<{ verified_at: Date | null }>(
      "SELECT verified_at FROM accounts WHERE email = $1",
      [email],
    );
    expect(account.rows[0]?.verified_at).not.toBeNull();

    const again = await redeem(t, token);
    expect(again.statusCode).toBe(401);
  });

  it("fails for an unknown link", async () => {
    expect((await redeem(t, "not-a-real-token")).statusCode).toBe(401);
  });

  it("fails for an expired link (clock moved past 15 minutes)", async () => {
    const { email, token } = await newLink();
    t.clock.advance(15 * 60 * 1000 + 1000);
    expect((await redeem(t, token)).statusCode).toBe(401);
    const account = await t.pool.query<{ verified_at: Date | null }>(
      "SELECT verified_at FROM accounts WHERE email = $1",
      [email],
    );
    expect(account.rows[0]?.verified_at).toBeNull();
  });

  it("still works just inside 15 minutes", async () => {
    const { token } = await newLink();
    t.clock.advance(14 * 60 * 1000);
    expect((await redeem(t, token)).statusCode).toBe(200);
  });

  it("lets only one of two simultaneous redeems win", async () => {
    const { token } = await newLink();
    const results = await Promise.all([redeem(t, token), redeem(t, token)]);
    expect(results.map((r) => r.statusCode).sort()).toEqual([200, 401]);
  });

  it("stores only hashes", async () => {
    const { token } = await newLink();
    const body = (await redeem(t, token)).json<{ refresh_token: string }>();
    registerSecret(body.refresh_token);

    const links = await t.pool.query<{ token_hash: Buffer }>(
      "SELECT token_hash FROM magic_links",
    );
    expect(links.rows).toHaveLength(1);
    expect(links.rows[0]?.token_hash.equals(hashToken(token))).toBe(true);
    const asText = await t.pool.query<{ j: string }>(
      "SELECT row_to_json(m)::text AS j FROM magic_links m",
    );
    expect(asText.rows.map((r) => r.j).join("")).not.toContain(token);

    const sessions = await t.pool.query<{ refresh_hash: Buffer }>(
      "SELECT refresh_hash FROM sessions",
    );
    expect(sessions.rows).toHaveLength(1);
    expect(
      sessions.rows[0]?.refresh_hash.equals(hashToken(body.refresh_token)),
    ).toBe(true);
    const sessionText = await t.pool.query<{ j: string }>(
      "SELECT row_to_json(s)::text AS j FROM sessions s",
    );
    expect(sessionText.rows.map((r) => r.j).join("")).not.toContain(
      body.refresh_token,
    );
  });

  it("sends a login link only to a verified account, with one fixed reply", async () => {
    const { email, token } = await newLink();
    const unverified = await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email },
    });
    const sentAfterUnverified = t.sender.messages.length;
    expect(unverified.statusCode).toBe(202);

    expect((await redeem(t, token)).statusCode).toBe(200);
    const verified = await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email },
    });
    const unknown = await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { email: uniqueEmail() },
    });
    expect(verified.statusCode).toBe(202);
    expect(unknown.statusCode).toBe(202);
    expect(verified.body).toBe(unknown.body);
    expect(verified.body).toBe(unverified.body);
    expect(sentAfterUnverified).toBe(1);
    expect(t.sender.messages).toHaveLength(2);

    const login = t.sender.lastTo(email);
    expect(login?.kind).toBe("login");
    const session = await redeem(t, (login as { token: string }).token);
    expect(session.statusCode).toBe(200);
  });

  it("voids older unused links when a new one is made", async () => {
    const { email, token } = await newLink();
    expect((await redeem(t, token)).statusCode).toBe(200);
    const send = () =>
      t.app.inject({
        method: "POST",
        url: "/v1/auth/login",
        payload: { email },
      });
    await send();
    const older = (t.sender.lastTo(email) as { token: string }).token;
    await send();
    const newer = (t.sender.lastTo(email) as { token: string }).token;
    expect(newer).not.toBe(older);
    expect((await redeem(t, older)).statusCode).toBe(401);
    expect((await redeem(t, newer)).statusCode).toBe(200);
  });

  it("answers sign-up the same for a new and an existing email", async () => {
    const email = uniqueEmail();
    const first = await signup(t, email);
    const second = await signup(t, email);
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    expect(second.body).toBe(first.body);
  });
});
