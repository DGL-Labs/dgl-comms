import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { deleteAccount } from "./account.ts";
import { isBlockedDomain } from "./blocklist.ts";
import { clientIp } from "./context.ts";
import type { Ctx } from "./context.ts";
import { first, withContext, withTx } from "./db.ts";
import { requireSession } from "./guard.ts";
import { isRecord, normalizeEmail } from "./input.ts";
import { createMagicLink } from "./magic.ts";
import { createSession, revokeAllSessions, revokeSession } from "./sessions.ts";
import type { IssuedSession } from "./sessions.ts";
import {
  LOGIN_LINK_LIMIT,
  WINDOW_MS,
  checkThrottle,
  lockKey,
  recordAttempt,
} from "./throttle.ts";
import { hashToken } from "./tokens.ts";
import { registerInvitationRoutes } from "./invitation-routes.ts";
import { registerKeyRoutes } from "./key-routes.ts";
import { registerPublishRoutes } from "./publish.ts";
import { registerTopicRoutes } from "./topic-routes.ts";
import { registerWorkspaceRoutes } from "./workspace-routes.ts";

const SIGNUP_CAP = 5;
const SIGNUP_WINDOW_MS = 24 * 60 * 60 * 1000;

// The same body for every sign-up and login that is accepted, so it does not
// reveal whether the email exists.
const ACCEPTED = { status: "accepted" };

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
  registerWorkspaceRoutes(app, ctx);
  registerInvitationRoutes(app, ctx);
  registerTopicRoutes(app, ctx);
  registerKeyRoutes(app, ctx);
  registerPublishRoutes(app, ctx);

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

    // The pause flag (disk guard, or an operator). Nothing is recorded for a
    // refused sign-up. A missing row fails closed.
    const flags = await withTx(ctx.pool, (tx) =>
      tx.query<{ paused: boolean }>(
        "SELECT signup_paused AS paused FROM service_limits",
      ),
    );
    if (first(flags.rows)?.paused !== false) {
      request.reason = "signup_paused";
      return reply.code(503).send({ error: "unavailable" });
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
      await ctx.sender.send({
        to: email,
        kind: "verify",
        token: outcome.token,
      });
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
    // Every request counts against the IP, known address or not, so the IP
    // limit hits all addresses at the same request number. Nothing is counted
    // per account, so a 429 never says anything about an account. The IP lock
    // makes the check and the record one step.
    const outcome = await withTx(ctx.pool, async (tx) => {
      await lockKey(tx, "ip", ip);
      const retryAfter = await checkThrottle(tx, now, ip);
      if (retryAfter > 0) return { kind: "throttled" as const, retryAfter };
      await recordAttempt(tx, now, ip);

      const found = await tx.query<{
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
        return { kind: "none" as const };
      }
      // At most LOGIN_LINK_LIMIT links per account per window. Over the cap,
      // the reply is the same but nothing is sent and no link is made.
      await lockKey(tx, "account", account.id);
      const sent = await tx.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM magic_links
          WHERE account_id = $1 AND purpose = 'login' AND created_at > $2`,
        [account.id, new Date(now.getTime() - WINDOW_MS)],
      );
      if (Number(first(sent.rows)?.n ?? "0") >= LOGIN_LINK_LIMIT) {
        return { kind: "capped" as const, accountId: account.id };
      }
      const token = await createMagicLink(tx, account.id, "login", now);
      return { kind: "sent" as const, accountId: account.id, token };
    });

    if (outcome.kind === "throttled") {
      return tooManyAttempts(request, reply, outcome.retryAfter);
    }
    if (outcome.kind === "sent") {
      request.accountId = outcome.accountId;
      await ctx.sender.send({ to: email, kind: "login", token: outcome.token });
      request.reason = "login_link_sent";
    } else if (outcome.kind === "capped") {
      request.accountId = outcome.accountId;
      request.reason = "login_link_capped";
    } else {
      request.reason = "login_unknown_or_unverified";
    }
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

    const outcome = await withTx(ctx.pool, async (tx) => {
      // A failed redeem counts against the IP only, never against the
      // account the link belongs to. The IP lock makes check and record one
      // step.
      await lockKey(tx, "ip", ip);
      const retryAfter = await checkThrottle(tx, now, ip);
      if (retryAfter > 0) return { kind: "throttled" as const, retryAfter };

      // Check and mark used in one statement: a link works once.
      const used = await tx.query<{ account_id: string; purpose: string }>(
        `UPDATE magic_links SET used_at = $2
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
          RETURNING account_id, purpose`,
        [hash, now],
      );
      const link = first(used.rows);
      let issued: IssuedSession | null = null;
      if (link !== undefined) {
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
        if (first(account.rows) !== undefined) {
          request.accountId = link.account_id;
          issued = await createSession(tx, ctx.key, link.account_id, now);
        }
      }
      if (issued === null) {
        await recordAttempt(tx, now, ip);
        return { kind: "invalid" as const };
      }
      return { kind: "ok" as const, issued };
    });

    if (outcome.kind === "throttled") {
      return tooManyAttempts(request, reply, outcome.retryAfter);
    }
    if (outcome.kind === "invalid") {
      request.reason = "invalid_link";
      return reply.code(401).send({ error: "invalid_link" });
    }
    request.reason = "redeemed";
    return reply.code(200).send(tokenBody(outcome.issued));
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
        chain_started_at: Date;
      }>(
        // Only an active account may refresh, and a chain ends 90 days after
        // its first session, however often it is rotated.
        `UPDATE sessions s SET revoked_at = $2
           FROM accounts a
          WHERE s.refresh_hash = $1 AND s.revoked_at IS NULL
            AND s.expires_at > $2
            AND s.chain_started_at + interval '90 days' >= $2
            AND a.id = s.account_id AND a.status = 'active'
          RETURNING s.id, s.account_id, s.device_id, s.chain_started_at`,
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
          old.chain_started_at,
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
      }>(
        "SELECT account_id, revoked_at FROM sessions WHERE refresh_hash = $1",
        [hash],
      );
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
    // ?confirm=true is needed only to delete solely-owned workspaces along
    // with the account. A shared workspace refuses the delete either way.
    const query = request.query;
    const confirm = isRecord(query) && query.confirm === "true";
    const outcome = await withContext(
      ctx.pool,
      { accountId: session.accountId },
      (tx) =>
        deleteAccount(tx, session.accountId, {
          confirm,
          now: ctx.clock.now(),
        }),
    );
    if (outcome.kind === "shared") {
      request.reason = "account_delete_shared";
      return reply.code(409).send({ owned_workspaces: outcome.workspaces });
    }
    if (outcome.kind === "confirm") {
      request.reason = "account_delete_confirm";
      return reply.code(409).send({
        owned_workspaces: outcome.workspaces.map((w) => ({
          id: w.id,
          action: "delete",
        })),
      });
    }
    ctx.sessionsRevoked(outcome.endedSessions);
    request.reason = "account_deleted";
    return reply.code(204).send();
  });
}
