import type { FastifyInstance, FastifyRequest } from "fastify";
import { writeAudit } from "./audit.ts";
import type { Ctx } from "./context.ts";
import { first, withContext } from "./db.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid, normalizeEmail } from "./input.ts";
import { hashToken, newToken } from "./tokens.ts";
import {
  authorize,
  badRequest,
  deny,
  memberRole,
  notFound,
} from "./workspaces.ts";

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const PER_ACCOUNT_PER_DAY = 20;
const PER_WORKSPACE_PER_DAY = 50;

function param(request: FastifyRequest, name: string): string | null {
  const params = request.params;
  const value = isRecord(params) ? params[name] : undefined;
  return isUuid(value) ? value : null;
}

export function registerInvitationRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/workspaces/:id/invitations {email, role}
  app.post("/v1/workspaces/:id/invitations", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const body = request.body;
    const email =
      isRecord(body) && typeof body.email === "string"
        ? normalizeEmail(body.email)
        : null;
    const role =
      isRecord(body) && (body.role === "admin" || body.role === "member")
        ? body.role
        : null;
    const now = ctx.clock.now();
    const me = session.accountId;
    const since = new Date(now.getTime() - DAY_MS);
    const token = newToken();

    const outcome = await withContext(
      ctx.pool,
      { accountId: me },
      async (tx) => {
        const decision = await authorize(ctx, tx, me, id, "invite.create");
        if (decision.kind !== "ok") return decision;
        // Validated after the permission check.
        if (email === null || role === null) {
          return { kind: "bad_request" as const };
        }
        // One invite at a time per inviting account, so its cap cannot be
        // raced from two workspaces.
        await tx.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [
          `invite:${me}`,
        ]);
        // Caps count audit rows, so cancelling an invite does not hand the
        // slot back.
        const byAccount = await tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM audit_log
            WHERE actor_account_id = $1 AND action = 'invite.create'
              AND at > $2`,
          [me, since],
        );
        if ((first(byAccount.rows)?.n ?? 0) >= PER_ACCOUNT_PER_DAY) {
          return { kind: "cap" as const, reason: "invite_cap_account" };
        }
        const byWorkspace = await tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM audit_log
            WHERE workspace_id = $1 AND action = 'invite.create'
              AND at > $2`,
          [id, since],
        );
        if ((first(byWorkspace.rows)?.n ?? 0) >= PER_WORKSPACE_PER_DAY) {
          return { kind: "cap" as const, reason: "invite_cap_workspace" };
        }
        // max_members counts members and pending invitations. A missing
        // limits row fails closed.
        const limits = await tx.query<{ max_members: number }>(
          "SELECT max_members FROM workspace_limits WHERE workspace_id = $1",
          [id],
        );
        const maxMembers = first(limits.rows)?.max_members;
        const members = await tx.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM members WHERE workspace_id = $1",
          [id],
        );
        const pending = await tx.query<{ n: number; same: number }>(
          `SELECT count(*)::int AS n,
                  (count(*) FILTER (WHERE email = $3))::int AS same
             FROM invitations
            WHERE workspace_id = $1 AND used_at IS NULL AND expires_at > $2`,
          [id, now, email],
        );
        const counted = first(pending.rows);
        if (
          maxMembers === undefined ||
          (first(members.rows)?.n ?? 0) + (counted?.n ?? 0) >= maxMembers
        ) {
          return { kind: "full" as const };
        }
        if ((counted?.same ?? 0) > 0) return { kind: "duplicate" as const };
        const made = await tx.query<{ id: string }>(
          `INSERT INTO invitations
             (workspace_id, invited_by, email, role, token_hash, expires_at, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
          [
            id,
            me,
            email,
            role,
            hashToken(token),
            new Date(now.getTime() + INVITE_TTL_MS),
            now,
          ],
        );
        const inviteId = first(made.rows)?.id;
        if (inviteId === undefined) {
          throw new Error("invitation insert returned no row");
        }
        await writeAudit(tx, now, {
          actorAccountId: me,
          workspaceId: id,
          action: "invite.create",
          target: inviteId,
          reason: role,
        });
        return { kind: "created" as const, inviteId };
      },
    );

    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "bad_request") return badRequest(request, reply);
    if (outcome.kind === "cap") {
      request.reason = outcome.reason;
      return reply.code(429).send({ error: "too_many_invitations" });
    }
    if (outcome.kind === "full") {
      request.reason = "member_limit";
      return reply.code(409).send({ error: "member_limit" });
    }
    if (outcome.kind === "duplicate") {
      request.reason = "already_invited";
      return reply.code(409).send({ error: "already_invited" });
    }
    // The token goes to the invitee by email only, never in the reply.
    await ctx.sender.send({ to: email as string, kind: "invite", token });
    request.reason = "invite_created";
    return reply.code(201).send({ id: outcome.inviteId });
  });

  // DELETE /v1/workspaces/:id/invitations/:inviteId (cancel)
  app.delete(
    "/v1/workspaces/:id/invitations/:inviteId",
    async (request, reply) => {
      const session = await requireSession(ctx, request, reply, {
        allowUnverified: false,
      });
      if (session === null) return reply;
      const id = param(request, "id");
      const inviteId = param(request, "inviteId");
      if (id === null || inviteId === null) return notFound(request, reply);
      const now = ctx.clock.now();

      const outcome = await withContext(
        ctx.pool,
        { accountId: session.accountId },
        async (tx) => {
          const decision = await authorize(
            ctx,
            tx,
            session.accountId,
            id,
            "invite.cancel",
          );
          if (decision.kind !== "ok") return decision;
          const removed = await tx.query(
            `DELETE FROM invitations
              WHERE id = $1 AND workspace_id = $2 AND used_at IS NULL`,
            [inviteId, id],
          );
          if (removed.rowCount !== 1) return { kind: "not_found" as const };
          await writeAudit(tx, now, {
            actorAccountId: session.accountId,
            workspaceId: id,
            action: "invite.cancel",
            target: inviteId,
          });
          return { kind: "done" as const };
        },
      );
      if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
        return deny(request, reply, outcome);
      }
      request.reason = "invite_cancelled";
      return reply.code(204).send();
    },
  );

  // POST /v1/invitations/accept {token}. Before success nothing about the
  // workspace is revealed: every failure is the same 404.
  app.post("/v1/invitations/accept", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
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
    const now = ctx.clock.now();
    const me = session.accountId;

    const outcome = await withContext(
      ctx.pool,
      { accountId: me, inviteHash: hash },
      async (tx, scope) => {
        // The token must exist, be unused and unexpired, and name the
        // caller's own verified email.
        const found = await tx.query<{ workspace_id: string }>(
          `SELECT i.workspace_id
             FROM invitations i JOIN accounts a ON a.id = $2 AND a.email = i.email
            WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > $3
              AND a.verified_at IS NOT NULL`,
          [hash, me, now],
        );
        const workspaceId = first(found.rows)?.workspace_id;
        if (workspaceId === undefined) return { kind: "invalid" as const };
        const locked = await tx.query(
          `SELECT id FROM workspaces
            WHERE id = $1 AND status = 'active' FOR UPDATE`,
          [workspaceId],
        );
        if (locked.rowCount !== 1) return { kind: "invalid" as const };
        // The token and the email both match, so this one workspace joins
        // the context. It is the only one the token can ever add.
        await scope.addWorkspaces([workspaceId]);
        if ((await memberRole(tx, workspaceId, me)) !== null) {
          return { kind: "member" as const };
        }
        const limits = await tx.query<{ max_members: number }>(
          "SELECT max_members FROM workspace_limits WHERE workspace_id = $1",
          [workspaceId],
        );
        const members = await tx.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM members WHERE workspace_id = $1",
          [workspaceId],
        );
        const maxMembers = first(limits.rows)?.max_members;
        if (
          maxMembers === undefined ||
          (first(members.rows)?.n ?? 0) >= maxMembers
        ) {
          return { kind: "full" as const };
        }
        // Check and mark used in one statement: an invitation works once.
        const claimed = await tx.query<{ id: string; role: string }>(
          `UPDATE invitations SET used_at = $2
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
              AND email = (SELECT email FROM accounts WHERE id = $3)
            RETURNING id, role`,
          [hash, now, me],
        );
        const invite = first(claimed.rows);
        if (invite === undefined) return { kind: "invalid" as const };
        await tx.query(
          `INSERT INTO members (workspace_id, account_id, role, created_at)
           VALUES ($1, $2, $3, $4)`,
          [workspaceId, me, invite.role, now],
        );
        await writeAudit(tx, now, {
          actorAccountId: me,
          workspaceId,
          action: "invite.accept",
          target: invite.id,
        });
        return { kind: "joined" as const, workspaceId };
      },
    );

    if (outcome.kind === "invalid") {
      request.reason = "invite_invalid";
      return reply.code(404).send({ error: "not_found" });
    }
    if (outcome.kind === "member") {
      request.reason = "already_member";
      return reply.code(409).send({ error: "already_member" });
    }
    if (outcome.kind === "full") {
      request.reason = "member_limit";
      return reply.code(409).send({ error: "member_limit" });
    }
    request.reason = "invite_accepted";
    return reply.code(200).send({ workspace_id: outcome.workspaceId });
  });
}
