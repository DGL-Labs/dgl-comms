import type { FastifyReply, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first } from "./db.ts";
import { readAccessToken } from "./sessions.ts";

export interface AuthedSession {
  accountId: string;
  sessionId: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function deny(
  request: FastifyRequest,
  reply: FastifyReply,
  status: 401 | 403,
  reason: string,
): null {
  request.reason = reason;
  void reply.code(status).send({
    error: status === 401 ? "unauthorized" : "forbidden",
  });
  return null;
}

// Auth middleware. Checks the bearer JWT and then the database: the session
// must exist, belong to the account, not be revoked and not be expired.
// Unverified accounts get 403 unless the route is an auth route
// (allowUnverified). On failure it has already sent the reply and returns null.
export async function requireSession(
  ctx: Ctx,
  request: FastifyRequest,
  reply: FastifyReply,
  options: { allowUnverified: boolean },
): Promise<AuthedSession | null> {
  const header = request.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return deny(request, reply, 401, "no_token");
  }
  const now = ctx.clock.now();
  const claims = await readAccessToken(ctx.key, header.slice(7), now);
  if (claims === null || !UUID.test(claims.accountId)) {
    return deny(request, reply, 401, "bad_token");
  }
  if (!UUID.test(claims.sessionId)) {
    return deny(request, reply, 401, "bad_token");
  }
  const result = await ctx.pool.query<{ verified_at: Date | null }>(
    `SELECT a.verified_at
       FROM sessions s JOIN accounts a ON a.id = s.account_id
      WHERE s.id = $1 AND s.account_id = $2
        AND s.revoked_at IS NULL AND s.expires_at > $3
        AND a.status = 'active'`,
    [claims.sessionId, claims.accountId, now],
  );
  const row = first(result.rows);
  if (row === undefined) return deny(request, reply, 401, "session_invalid");
  request.accountId = claims.accountId;
  if (row.verified_at === null && !options.allowUnverified) {
    return deny(request, reply, 403, "unverified");
  }
  return claims;
}
