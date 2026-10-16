import { afterEach, describe, expect, it } from "vitest";
import { newToken } from "../../src/tokens.ts";
import {
  makeApp,
  redeem,
  signup,
  signupAndVerify,
  trustedProxies,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

// T-THROTTLE
describe("T-THROTTLE", () => {
  let t: TestApp;
  afterEach(() => t.close());

  it("never counts a replayed link against its account", async () => {
    t = await makeApp({ allowlistOn: false });
    const email = uniqueEmail();
    await signup(t, email);
    const link = (t.sender.lastTo(email) as { token: string }).token;
    expect((await redeem(t, link)).statusCode).toBe(200);

    // The link is used now. Each replay comes from its own IP, so none is
    // throttled, and none is recorded against the account.
    for (let i = 1; i <= 10; i++) {
      const res = await redeem(t, link, `198.51.100.${i}`);
      expect(res.statusCode).toBe(401);
    }
    const rows = await t.pool.query(
      "SELECT 1 FROM login_failures WHERE account_id IS NOT NULL",
    );
    expect(rows.rowCount).toBe(0);
  });

  it("gives 429 on the 21st failure from one IP", async () => {
    t = await makeApp({ allowlistOn: false });
    for (let i = 1; i <= 20; i++) {
      const res = await redeem(t, newToken(), "203.0.113.5");
      expect(res.statusCode).toBe(401);
    }
    const next = await redeem(t, newToken(), "203.0.113.5");
    expect(next.statusCode).toBe(429);
    const retryAfter = Number(next.headers["retry-after"]);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(900);

    // The window passes and the IP may try again.
    t.clock.advance(15 * 60 * 1000 + 1000);
    expect((await redeem(t, newToken(), "203.0.113.5")).statusCode).toBe(401);
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

  it("throttles known and unknown login emails at the same request", async () => {
    t = await makeApp({ allowlistOn: false });
    const known = uniqueEmail();
    await signupAndVerify(t, known);
    const login = (email: string, remoteAddress: string) =>
      t.app.inject({
        method: "POST",
        url: "/v1/auth/login",
        remoteAddress,
        payload: { email },
      });

    // Each address comes from its own IP. The reply and the 21st-request
    // limit are the same for both.
    for (let i = 1; i <= 20; i++) {
      expect((await login(known, "203.0.113.30")).statusCode).toBe(202);
      expect((await login(uniqueEmail(), "203.0.113.31")).statusCode).toBe(202);
    }
    const knownNext = await login(known, "203.0.113.30");
    const unknownNext = await login(uniqueEmail(), "203.0.113.31");
    expect(knownNext.statusCode).toBe(429);
    expect(unknownNext.statusCode).toBe(429);
    expect(knownNext.body).toBe(unknownNext.body);
  });

  it("sends a known email at most 3 login links in 15 minutes", async () => {
    t = await makeApp({ allowlistOn: false });
    const email = uniqueEmail();
    await signupAndVerify(t, email);
    const logins = () =>
      t.sender.messages.filter((m) => m.to === email && m.kind === "login");

    const bodies = new Set<string>();
    for (let i = 1; i <= 6; i++) {
      const res = await t.app.inject({
        method: "POST",
        url: "/v1/auth/login",
        remoteAddress: "203.0.113.40",
        payload: { email },
      });
      expect(res.statusCode).toBe(202);
      bodies.add(res.body);
    }
    // The reply is the same whether or not a link was sent.
    expect(bodies.size).toBe(1);
    expect(logins()).toHaveLength(3);
    const links = await t.pool.query(
      "SELECT 1 FROM magic_links WHERE purpose = 'login'",
    );
    expect(links.rowCount).toBe(3);

    // The window passes and a link goes out again.
    t.clock.advance(15 * 60 * 1000 + 1000);
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      remoteAddress: "203.0.113.40",
      payload: { email },
    });
    expect(logins()).toHaveLength(4);
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
      "SELECT DISTINCT host(ip) AS ip FROM login_failures",
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
      "SELECT host(ip) AS ip FROM login_failures",
    );
    expect(ips.rows.map((r) => r.ip)).toEqual(["192.0.2.77"]);
  });
});
