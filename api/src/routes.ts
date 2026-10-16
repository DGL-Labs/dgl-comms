import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { deleteAccount } from "./account.ts";
import { isBlockedDomain } from "./blocklist.ts";
import { clientIp } from "./context.ts";
import type { Ctx } from "./context.ts";
import { first, withTx } from "./db.ts";
import { requireSession } from "./guard.ts";
import { createMagicLink } from "./magic.ts";
import {
  createSession,
  revokeAllSessions,
  revokeSession,
} from "./sessions.ts";
import type { IssuedSession } from "./sessions.ts";
import { checkThrottle, recordFailure } from "./throttle.ts";
import { hashToken } from "./tokens.ts";

const SIGNUP_CAP = 5;
const SIGNUP_WINDOW_MS = 24 * 60 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The same body for every sign-up and login that is accepted, so it does not
// reveal whether the email exists.
const ACCEPTED = { status: "accepted" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeEmail(raw: string): string | null {
  const email = raw.trim().toLowerCase();
  return email.length <= 254 && EMAIL_PATTERN.test(email) ? email : null;
}

function badRequest(request: FastifyRequest, reply: FastifyReply) {
  request.reason = "bad_request";
  return reply.code(400).send({ error: "bad_request" });
}

function tooManyAttempts(
  request: FastifyRequest,
  reply: FastifyReply,
  retryAfter: number,
) {
  request.reason = "throttled";
  return reply
    .header("Retry-After", String(retryAfter))
    .code(429)
    .send({ error: "too_many_attempts" });
}

function tokenBody(issued: IssuedSession) {
  return {
    access_token: issued.accessToken,
    refresh_token: issued.refreshToken,
    token_type: "Bearer",
    expires_in: issued.expiresIn,
  };
}

function signupRefused(
  request: FastifyRequest,
  reply: FastifyReply,
  status: 403 | 429,
  reason: string,
) {
  request.reason = reason;
  return reply.code(status).send({ error: "signup_refused" });
}

export function registerRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/auth/signup
  app.post("/v1/auth/signup", async (request, reply) => {
    const body = request.body;
    if (
      !isRecord(body) ||
      typeof body.email !== "string" ||
      typeof body.age_attested !== "boolean"
    ) {
      return badRequest(request, reply);
    }
    const email = normalizeEmail(body.email);
    if (email === null) return badRequest(request, reply);

    if (!body.age_attested) {
      return signupRefused(request, reply, 403, "age_not_attested");
    }
    if (ctx.config.allowlistOn && !ctx.config.allowlist.has(email)) {
      return signupRefused(request, reply, 403, "not_allowlisted");
    }
    const domain = email.slice(email.lastIndexOf("@") + 1);
    if (isBlockedDomain(ctx.blocklist, domain)) {
      return signupRefused(request, reply, 403, "disposable_domain");
    }

    const ip = clientIp(ctx, request);
    const now = ctx.clock.now();
    const outcome = await withTx(ctx.pool, async (tx) => {
      // One sign-up per IP at a time, so the cap cannot be raced.
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [ip]);
      const counted = await tx.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM signup_events
          WHERE ip = $1 AND created_at > $2`,
        [ip, new Date(now.getTime() - SIGNUP_WINDOW_MS)],
      );
      if (Number(first(counted.rows)?.n ?? "0") >= SIGNUP_CAP) {
        return { capped: true as const };
      }
      await tx.query(
        "INSERT INTO signup_events (ip, created_at) VALUES ($1, $2)",
        [ip, now],
      );
      // An existing email is not an error: nothing changes and the reply is
      // the same. An existing unverified account gets a fresh verify link.
      const account = await tx.query<{ id: string; verified_at: Date | null }>(
        `INSERT INTO accounts (email, age_attested_at, created_at)
         VALUES ($1, $2, $2)
         ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
         RETURNING id, verified_at`,
        [email, now],
      );
      const row = first(account.rows);
      if (row === undefined) throw new Error("account upsert returned no row");
      request.accountId = row.id;
      if (row.verified_at !== null) {
        return { capped: false as const, token: null };
      }
      const token = await createMagicLink(tx, row.id, "verify", now);
      return { capped: false as const, token };
    });

    if (outcome.capped) {
      return signupRefused(request, reply, 429, "signup_cap");
    }
    if (outcome.token !== null) {
      await ctx.sender.send({ to: email, kind: "verify", token: outcome.token });
    }
    request.reason = "signup_accepted";
    return reply.code(202).send(ACCEPTED);
  });

  // POST /v1/auth/login
  app.post("/v1/auth/login", async (request, reply) => {
    const body = request.body;
    if (!isRecord(body) || typeof body.email !== "string") {
      return badRequest(request, reply);
    }
    const email = normalizeEmail(body.email);
    if (email === null) return badRequest(request, reply);

    const ip = clientIp(ctx, request);
    const now = ctx.clock.now();
    // Failures here are counted per IP only. Counting them per account would
    // let a 429 tell an attacker that an unverified account exists.
    const retryAfter = await checkThrottle(ctx.pool, now, null, ip);
    if (retryAfter > 0) return tooManyAttempts(request, reply, retryAfter);

    const found = await ctx.pool.query<{
      id: string;
      verified_at: Date | null;
      status: string;
    }>("SELECT id, verified_at, status FROM accounts WHERE email = $1", [
      email,
    ]);
    const account = first(found.rows);
    if (
      account === undefined ||
      account.verified_at === null ||
      account.status !== "active"
    ) {
      await recordFailure(ctx.pool, now, null, ip);
      request.reason = "login_unknown_or_unverified";
      return reply.code(202).send(ACCEPTED);
    }
    request.accountId = account.id;
    const token = await createMagicLink(ctx.pool, account.id, "login", now);
    await ctx.sender.send({ to: email, kind: "login", token });
    request.reason = "login_link_sent";
    return reply.code(202).send(ACCEPTED);
  });

  // POST /v1/auth/redeem (both purposes)
  app.post("/v1/auth/redeem", async (request, reply) => {
    const body = request.body;
    if (
      !isRecord(body) ||
      typeof body.token !== "string" ||
      body.token === "" ||
      body.token.length > 200
    ) {
      return badRequest(request, reply);
    }
    const hash = hashToken(body.token);
    const ip = clientIp(ctx, request);
    const now = ctx.clock.now();

    // Attribute failures to the link's account when the link is known.
    const known = await ctx.pool.query<{ account_id: string }>(
      "SELECT account_id FROM magic_links WHERE token_hash = $1",
      [hash],
    );
    const knownAccountId = first(known.rows)?.account_id ?? null;
    const retryAfter = await checkThrottle(ctx.pool, now, knownAccountId, ip);
    if (retryAfter > 0) return tooManyAttempts(request, reply, retryAfter);

    const issued = await withTx(ctx.pool, async (tx) => {
      // Check and mark used in one statement: a link works once.
      const used = await tx.query<{ account_id: string; purpose: string }>(
        `UPDATE magic_links SET used_at = $2
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
          RETURNING account_id, purpose`,
        [hash, now],
      );
      const link = first(used.rows);
      if (link === undefined) return null;
      const account =
        link.purpose === "verify"
          ? await tx.query<{ id: string }>(
              `UPDATE accounts SET verified_at = COALESCE(verified_at, $2)
                WHERE id = $1 AND status = 'active' RETURNING id`,
              [link.account_id, now],
            )
          : await tx.query<{ id: string }>(
              `SELECT id FROM accounts
                WHERE id = $1 AND status = 'active' AND verified_at IS NOT NULL`,
              [link.account_id],
            );
      if (first(account.rows) === undefined) return null;
      request.accountId = link.account_id;
      return createSession(tx, ctx.key, link.account_id, now);
    });

    if (issued === null) {
      await recordFailure(ctx.pool, now, knownAccountId, ip);
      request.reason = "invalid_link";
      return reply.code(401).send({ error: "invalid_link" });
    }
    request.reason = "redeemed";
    return reply.code(200).send(tokenBody(issued));
  });

  // POST /v1/auth/refresh: rotates the refresh token. A new session row is
  // issued and the old one revoked, so reuse of the old token is detectable.
  app.post("/v1/auth/refresh", async (request, reply) => {
    const body = request.body;
    if (
      !isRecord(body) ||
      typeof body.refresh_token !== "string" ||
      body.refresh_token === "" ||
      body.refresh_token.length > 200
    ) {
      return badRequest(request, reply);
    }
    const hash = hashToken(body.refresh_token);
    const now = ctx.clock.now();

    const outcome = await withTx(ctx.pool, async (tx) => {
      const rotated = await tx.query<{
        id: string;
        account_id: string;
        device_id: string | null;
      }>(
        `UPDATE sessions SET revoked_at = $2
          WHERE refresh_hash = $1 AND revoked_at IS NULL AND expires_at > $2
          RETURNING id, account_id, device_id`,
        [hash, now],
      );
      const old = first(rotated.rows);
      if (old !== undefined) {
        const issued = await createSession(
          tx,
          ctx.key,
          old.account_id,
          now,
          old.device_id,
        );
        return {
          kind: "ok" as const,
          issued,
          accountId: old.account_id,
          revoked: [old.id],
        };
      }
      const seen = await tx.query<{
        account_id: string;
        revoked_at: Date | null;
      }>("SELECT account_id, revoked_at FROM sessions WHERE refresh_hash = $1", [
        hash,
      ]);
      const session = first(seen.rows);
      if (session !== undefined && session.revoked_at !== null) {
        // A revoked refresh token came back: treat the account as compromised.
        const revoked = await revokeAllSessions(tx, session.account_id, now);
        return {
          kind: "reuse" as const,
          accountId: session.account_id,
          revoked,
        };
      }
      return { kind: "invalid" as const, revoked: [] as string[] };
    });

    ctx.sessionsRevoked(outcome.revoked);
    if (outcome.kind === "ok") {
      request.accountId = outcome.accountId;
      request.reason = "refreshed";
      return reply.code(200).send(tokenBody(outcome.issued));
    }
    if (outcome.kind === "reuse") {
      request.accountId = outcome.accountId;
      request.reason = "refresh_reuse";
    } else {
      request.reason = "refresh_invalid";
    }
    return reply.code(401).send({ error: "invalid_refresh_token" });
  });

  // POST /v1/auth/logout and /v1/auth/logout-all are auth routes, so an
  // unverified session may use them.
  app.post("/v1/auth/logout", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: true,
    });
    if (session === null) return reply;
    const revoked = await revokeSession(
      ctx.pool,
      session.sessionId,
      ctx.clock.now(),
    );
    ctx.sessionsRevoked(revoked);
    request.reason = "logout";
    return reply.code(204).send();
  });

  app.post("/v1/auth/logout-all", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: true,
    });
    if (session === null) return reply;
    const revoked = await revokeAllSessions(
      ctx.pool,
      session.accountId,
      ctx.clock.now(),
    );
    ctx.sessionsRevoked(revoked);
    request.reason = "logout_all";
    return reply.code(204).send();
  });

  // DELETE /v1/account
  app.delete("/v1/account", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const ended = await withTx(ctx.pool, (tx) =>
      deleteAccount(tx, session.accountId),
    );
    ctx.sessionsRevoked(ended);
    request.reason = "account_deleted";
    return reply.code(204).send();
  });
}
