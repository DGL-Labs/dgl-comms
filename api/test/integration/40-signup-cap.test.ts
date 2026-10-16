import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeApp, signup, trustedProxies, uniqueEmail } from "./harness.ts";
import type { TestApp } from "./harness.ts";

// T-SIGNUP-CAP
describe("T-SIGNUP-CAP", () => {
  let t: TestApp;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
  });
  afterEach(() => t.close());

  it("refuses the 6th sign-up from one IP in 24 hours", async () => {
    for (let i = 0; i < 5; i++) {
      expect((await signup(t, uniqueEmail(), "192.0.2.50")).statusCode).toBe(
        202,
      );
    }
    const sixth = await signup(t, uniqueEmail(), "192.0.2.50");
    expect(sixth.statusCode).toBe(429);
    const accounts = await t.pool.query("SELECT 1 FROM accounts");
    expect(accounts.rowCount).toBe(5);
    expect(t.sender.messages).toHaveLength(5);

    // Another IP is fine.
    expect((await signup(t, uniqueEmail(), "192.0.2.51")).statusCode).toBe(202);
  });

  it("allows sign-ups again after 24 hours", async () => {
    for (let i = 0; i < 5; i++) await signup(t, uniqueEmail(), "192.0.2.60");
    expect((await signup(t, uniqueEmail(), "192.0.2.60")).statusCode).toBe(429);
    t.clock.advance(24 * 60 * 60 * 1000 + 1000);
    expect((await signup(t, uniqueEmail(), "192.0.2.60")).statusCode).toBe(202);
  });

  it("counts concurrent sign-ups against the cap", async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () => signup(t, uniqueEmail(), "192.0.2.70")),
    );
    const codes = results.map((r) => r.statusCode);
    expect(codes.filter((c) => c === 202)).toHaveLength(5);
    expect(codes.filter((c) => c === 429)).toHaveLength(3);
  });

  it("does not let CF-Connecting-IP from an untrusted peer dodge the cap", async () => {
    for (let i = 0; i < 5; i++) await signup(t, uniqueEmail(), "192.0.2.80");
    const res = await t.app.inject({
      method: "POST",
      url: "/v1/auth/signup",
      remoteAddress: "192.0.2.80",
      headers: { "cf-connecting-ip": "192.0.2.81" },
      payload: { email: uniqueEmail(), age_attested: true },
    });
    expect(res.statusCode).toBe(429);
  });

  it("counts by the forwarded IP behind a trusted proxy", async () => {
    await t.close();
    t = await makeApp({
      allowlistOn: false,
      trustedProxies: trustedProxies("192.0.2.0/24"),
    });
    const viaProxy = (forwarded: string) =>
      t.app.inject({
        method: "POST",
        url: "/v1/auth/signup",
        remoteAddress: "192.0.2.1",
        headers: { "cf-connecting-ip": forwarded },
        payload: { email: uniqueEmail(), age_attested: true },
      });
    for (let i = 0; i < 5; i++) await viaProxy("198.51.100.200");
    expect((await viaProxy("198.51.100.200")).statusCode).toBe(429);
    expect((await viaProxy("198.51.100.201")).statusCode).toBe(202);
  });
});
