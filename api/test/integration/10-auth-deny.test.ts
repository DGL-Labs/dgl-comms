import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSession } from "../../src/sessions.ts";
import {
  bearer,
  makeApp,
  signup,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

// T-AUTH-DENY
describe("T-AUTH-DENY", () => {
  let t: TestApp;

  beforeEach(async () => {
    t = await makeApp(
      { allowlistOn: true, allowlist: new Set(["a@example.test"]) },
      new Set(["blocked.example.test"]),
    );
  });
  afterEach(() => t.close());

  const del = (headers: Record<string, string> = {}) =>
    t.app.inject({ method: "DELETE", url: "/v1/account", headers });

  it("gives 401 with no token", async () => {
    expect((await del()).statusCode).toBe(401);
  });

  it("gives 401 for a malformed authorization header", async () => {
    expect((await del({ authorization: "Basic abc" })).statusCode).toBe(401);
    expect((await del({ authorization: "Bearer nonsense" })).statusCode).toBe(
      401,
    );
  });

  it("gives 401 for an expired token", async () => {
    const { accessToken } = await signupAndVerify(t, "a@example.test");
    t.clock.advance(16 * 60 * 1000);
    expect((await del(bearer(accessToken))).statusCode).toBe(401);
  });

  it("gives 401 for a revoked session", async () => {
    const { accessToken } = await signupAndVerify(t, "a@example.test");
    const out = await t.app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: bearer(accessToken),
    });
    expect(out.statusCode).toBe(204);
    expect((await del(bearer(accessToken))).statusCode).toBe(401);
  });

  it("gives 401 for a tampered token", async () => {
    const { accessToken } = await signupAndVerify(t, "a@example.test");
    // Change a character inside the signature (the last one only carries
    // padding bits, so it is not used).
    const i = accessToken.length - 10;
    const swapped = accessToken[i] === "A" ? "B" : "A";
    const tampered =
      accessToken.slice(0, i) + swapped + accessToken.slice(i + 1);
    expect((await del(bearer(tampered))).statusCode).toBe(401);
  });

  it("gives 401 for a token with a tampered payload", async () => {
    const { accessToken } = await signupAndVerify(t, "a@example.test");
    const [head, , sig] = accessToken.split(".") as [string, string, string];
    const forged = Buffer.from(
      JSON.stringify({ sub: "00000000-0000-4000-8000-000000000000" }),
    ).toString("base64url");
    expect((await del(bearer(`${head}.${forged}.${sig}`))).statusCode).toBe(
      401,
    );
  });

  it("gives 403 to an unverified account, except on auth routes", async () => {
    const res = await signup(t, "a@example.test");
    expect(res.statusCode).toBe(202);
    const account = await t.pool.query<{ id: string }>(
      "SELECT id FROM accounts WHERE email = 'a@example.test'",
    );
    const accountId = (account.rows[0] as { id: string }).id;
    const key = new TextEncoder().encode(t.config.jwtKey);
    const issued = await createSession(t.pool, key, accountId, t.clock.now());
    const headers = bearer(issued.accessToken);
    expect((await del(headers)).statusCode).toBe(403);
    const out = await t.app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers,
    });
    expect(out.statusCode).toBe(204);
  });

  it("accepts a valid token (positive control)", async () => {
    const { accessToken } = await signupAndVerify(t, "a@example.test");
    const out = await t.app.inject({
      method: "POST",
      url: "/v1/auth/logout-all",
      headers: bearer(accessToken),
    });
    expect(out.statusCode).toBe(204);
  });

  it("refuses a non-allowlisted email while the allowlist is on", async () => {
    const email = uniqueEmail();
    const res = await signup(t, email);
    expect(res.statusCode).toBe(403);
    expect(t.sender.messages).toHaveLength(0);
    const rows = await t.pool.query("SELECT 1 FROM accounts");
    expect(rows.rowCount).toBe(0);
  });

  it("refuses a blocklisted domain and its subdomains", async () => {
    await t.close();
    t = await makeApp(
      { allowlistOn: false },
      new Set(["blocked.example.test"]),
    );
    for (const email of [
      "u@blocked.example.test",
      "u@sub.blocked.example.test",
    ]) {
      const res = await signup(t, email);
      expect(res.statusCode).toBe(403);
    }
    expect(t.sender.messages).toHaveLength(0);
    const ok = await signup(t, uniqueEmail());
    expect(ok.statusCode).toBe(202);
  });

  it("refuses sign-up without the age attestation", async () => {
    const res = await t.app.inject({
      method: "POST",
      url: "/v1/auth/signup",
      payload: { email: "a@example.test", age_attested: false },
    });
    expect(res.statusCode).toBe(403);
    const bad = await t.app.inject({
      method: "POST",
      url: "/v1/auth/signup",
      payload: { email: "a@example.test" },
    });
    expect(bad.statusCode).toBe(400);
  });
});
