import { afterEach, describe, expect, it } from "vitest";
import { newToken } from "../../src/tokens.ts";
import {
  makeApp,
  redeem,
  signup,
  trustedProxies,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

// T-THROTTLE
describe("T-THROTTLE", () => {
  let t: TestApp;
  afterEach(() => t.close());

  it("gives 429 on the 6th failure for one account", async () => {
    t = await makeApp({ allowlistOn: false });
    const email = uniqueEmail();
    await signup(t, email);
    const link = (t.sender.lastTo(email) as { token: string }).token;
    expect((await redeem(t, link)).statusCode).toBe(200);

    // The link is used now, so every further try is a failure for its account.
    // Different IPs each time: this limit is per account.
    for (let i = 1; i <= 5; i++) {
      const res = await redeem(t, link, `198.51.100.${i}`);
      expect(res.statusCode).toBe(401);
    }
    const sixth = await redeem(t, link, "198.51.100.99");
    expect(sixth.statusCode).toBe(429);
    const retryAfter = Number(sixth.headers["retry-after"]);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(900);

    // The window passes and the account may try again.
    t.clock.advance(15 * 60 * 1000 + 1000);
    expect((await redeem(t, link, "198.51.100.99")).statusCode).toBe(401);
  });

  it("gives 429 on the 21st failure from one IP", async () => {
    t = await makeApp({ allowlistOn: false });
    for (let i = 1; i <= 20; i++) {
      const res = await redeem(t, newToken(), "203.0.113.5");
      expect(res.statusCode).toBe(401);
    }
    const next = await redeem(t, newToken(), "203.0.113.5");
    expect(next.statusCode).toBe(429);
    expect(next.headers["retry-after"]).toBeDefined();
    // Another IP is not affected.
    expect((await redeem(t, newToken(), "203.0.113.6")).statusCode).toBe(401);
  });

  it("counts failed login requests for unknown addresses per IP", async () => {
    t = await makeApp({ allowlistOn: false });
    for (let i = 1; i <= 20; i++) {
      const res = await t.app.inject({
        method: "POST",
        url: "/v1/auth/login",
        remoteAddress: "203.0.113.7",
        payload: { email: uniqueEmail() },
      });
      expect(res.statusCode).toBe(202);
    }
    const next = await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      remoteAddress: "203.0.113.7",
      payload: { email: uniqueEmail() },
    });
    expect(next.statusCode).toBe(429);
    expect(next.headers["retry-after"]).toBeDefined();
  });

  it("ignores CF-Connecting-IP from an untrusted peer", async () => {
    t = await makeApp({ allowlistOn: false });
    for (let i = 1; i <= 20; i++) {
      const res = await redeem(t, newToken(), "203.0.113.20", {
        "cf-connecting-ip": `192.0.2.${i}`,
      });
      expect(res.statusCode).toBe(401);
    }
    // The header changes every time, yet the peer is what is counted.
    const next = await redeem(t, newToken(), "203.0.113.20", {
      "cf-connecting-ip": "192.0.2.200",
    });
    expect(next.statusCode).toBe(429);
    const ips = await t.pool.query<{ ip: string }>(
      "SELECT DISTINCT ip::text AS ip FROM login_failures",
    );
    expect(ips.rows.map((r) => r.ip)).toEqual(["203.0.113.20"]);
  });

  it("uses CF-Connecting-IP when the peer is a trusted proxy", async () => {
    t = await makeApp({
      allowlistOn: false,
      trustedProxies: trustedProxies("203.0.113.0/24"),
    });
    const res = await redeem(t, newToken(), "203.0.113.9", {
      "cf-connecting-ip": "192.0.2.77",
    });
    expect(res.statusCode).toBe(401);
    const ips = await t.pool.query<{ ip: string }>(
      "SELECT ip::text AS ip FROM login_failures",
    );
    expect(ips.rows.map((r) => r.ip)).toEqual(["192.0.2.77"]);
  });
});
