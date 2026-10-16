import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SignJWT, decodeJwt } from "jose";
import { createSession } from "../../src/sessions.ts";
import {
  bearer,
  makeApp,
  signup,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp, Tokens } from "./harness.ts";

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

  describe("forged tokens", () => {
    interface Forge {
      alg?: "HS256" | "HS512";
      secret?: Uint8Array;
      iss?: string | null;
      aud?: string | null;
      kid?: string | null;
      sid?: string | null;
    }

    // A token for a real account and session, with one thing changed.
    async function forge(tokens: Tokens, opts: Forge = {}): Promise<string> {
      const claims = decodeJwt(tokens.accessToken);
      const iat = Math.floor(t.clock.now().getTime() / 1000);
      const payload = opts.sid === null ? {} : { sid: opts.sid ?? claims.sid };
      const kid = opts.kid ?? t.config.jwtKid;
      const header = { alg: opts.alg ?? "HS256", ...(kid ? { kid } : {}) };
      const jwt = new SignJWT(payload)
        .setProtectedHeader(opts.kid === null ? { alg: header.alg } : header)
        .setSubject(tokens.accountId)
        .setIssuedAt(iat)
        .setExpirationTime(iat + 900);
      if (opts.iss !== null) jwt.setIssuer(opts.iss ?? "pingzo-api");
      if (opts.aud !== null) jwt.setAudience(opts.aud ?? "pingzo-app");
      return jwt.sign(opts.secret ?? new TextEncoder().encode(t.config.jwtKey));
    }

    const encode = (value: object) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");

    it("accepts a correctly forged token (positive control)", async () => {
      const tokens = await signupAndVerify(t, "a@example.test");
      const out = await t.app.inject({
        method: "POST",
        url: "/v1/auth/logout",
        headers: bearer(await forge(tokens)),
      });
      expect(out.statusCode).toBe(204);
    });

    it("gives 401 for alg none, other algs, keys, claims and kid", async () => {
      const tokens = await signupAndVerify(t, "a@example.test");
      const claims = decodeJwt(tokens.accessToken);
      const iat = Math.floor(t.clock.now().getTime() / 1000);
      const noneHeader = encode({ alg: "none", kid: t.config.jwtKid });
      const nonePayload = encode({
        sub: tokens.accountId,
        sid: claims.sid,
        iss: "pingzo-api",
        aud: "pingzo-app",
        iat,
        exp: iat + 900,
      });
      const algNone = `${noneHeader}.${nonePayload}.`;
      const otherKey = new TextEncoder().encode(
        "a-different-key-a-different-key-0000",
      );
      const forged: Record<string, string> = {
        "alg none": algNone,
        "HS512 with the same key": await forge(tokens, { alg: "HS512" }),
        "different key": await forge(tokens, { secret: otherKey }),
        "wrong iss": await forge(tokens, { iss: "someone-else" }),
        "no iss": await forge(tokens, { iss: null }),
        "wrong aud": await forge(tokens, { aud: "someone-else" }),
        "no aud": await forge(tokens, { aud: null }),
        "wrong kid": await forge(tokens, { kid: "k-other" }),
        "no kid": await forge(tokens, { kid: null }),
        "no sid": await forge(tokens, { sid: null }),
      };
      for (const [name, token] of Object.entries(forged)) {
        const res = await del(bearer(token));
        expect(res.statusCode, name).toBe(401);
      }
      // None of them touched the real session.
      const out = await t.app.inject({
        method: "POST",
        url: "/v1/auth/logout-all",
        headers: bearer(tokens.accessToken),
      });
      expect(out.statusCode).toBe(204);
    });

    it("gives 401 for a token of a deleted account", async () => {
      const tokens = await signupAndVerify(t, "a@example.test");
      const valid = await forge(tokens);
      expect((await del(bearer(tokens.accessToken))).statusCode).toBe(204);
      expect((await del(bearer(valid))).statusCode).toBe(401);
      expect((await del(bearer(tokens.accessToken))).statusCode).toBe(401);
    });
  });

  it("gives 403 to an unverified account, except on auth routes", async () => {
    const res = await signup(t, "a@example.test");
    expect(res.statusCode).toBe(202);
    const account = await t.pool.query<{ id: string }>(
      "SELECT id FROM accounts WHERE email = 'a@example.test'",
    );
    const accountId = (account.rows[0] as { id: string }).id;
    const key = {
      secret: new TextEncoder().encode(t.config.jwtKey),
      kid: t.config.jwtKid,
    };
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
