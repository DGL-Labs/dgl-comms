import type { FastifyInstance, FastifyRequest } from "fastify";
import { writeAudit } from "./audit.ts";
import type { Ctx } from "./context.ts";
import { first, withContext, withPathContext } from "./db.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid, parseName } from "./input.ts";
import { can, isRole } from "./permissions.ts";
import type { Role } from "./permissions.ts";
import {
  authorize,
  badRequest,
  deny,
  forbidden,
  memberRole,
  notFound,
} from "./workspaces.ts";

const MAX_OWNED_WORKSPACES = 3;

// A path parameter that is a uuid, else null (the route then gives 404).
function param(request: FastifyRequest, name: string): string | null {
  const params = request.params;
  const value = isRecord(params) ? params[name] : undefined;
  return isUuid(value) ? value : null;
}

export function registerWorkspaceRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/workspaces
  app.post("/v1/workspaces", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const body = request.body;
    const name = isRecord(body) ? parseName(body.name) : null;
    const kind = isRecord(body) ? body.kind : undefined;
    // dgl_internal is never created through the API.
    if (name === null || (kind !== "client" && kind !== "team")) {
      return badRequest(request, reply);
    }
    const now = ctx.clock.now();
    const me = session.accountId;

    const outcome = await withContext(
      ctx.pool,
      { accountId: me },
      async (tx, scope) => {
        // The pause flag. A missing row fails closed.
        const flags = await tx.query<{ paused: boolean }>(
          "SELECT signup_paused AS paused FROM service_limits",
        );
        if (first(flags.rows)?.paused !== false) {
          return { kind: "paused" as const };
        }
        // One workspace creation per account at a time, so the cap cannot be
        // raced.
        await tx.query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE", [
          me,
        ]);
        const owned = await tx.query<{ n: number | null }>(
          "SELECT count_owned_workspaces($1) AS n",
          [me],
        );
        // A missing count fails closed.
        const ownedCount = first(owned.rows)?.n;
        if (
          ownedCount === undefined ||
          ownedCount === null ||
          ownedCount >= MAX_OWNED_WORKSPACES
        ) {
          return { kind: "too_many" as const };
        }
        // The global ceiling. A missing row fails closed.
        await tx.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [
          "workspace_ceiling",
        ]);
        const ceiling = await tx.query<{ ceiling: number }>(
          "SELECT max_workspaces_total AS ceiling FROM service_limits",
        );
        const total = await tx.query<{ n: number | null }>(
          "SELECT count_workspaces_total() AS n",
        );
        const limit = first(ceiling.rows)?.ceiling;
        const totalCount = first(total.rows)?.n;
        if (
          limit === undefined ||
          totalCount === undefined ||
          totalCount === null ||
          totalCount >= limit
        ) {
          return { kind: "ceiling" as const };
        }
        const made = await tx.query<{ id: string }>(
          `INSERT INTO workspaces (owner_id, name, kind, created_at)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [me, name, kind, now],
        );
        const id = first(made.rows)?.id;
        if (id === undefined) {
          throw new Error("workspace insert returned no row");
        }
        await tx.query(
          "INSERT INTO workspace_limits (workspace_id) VALUES ($1)",
          [id],
        );
        // The new workspace joins the context before its first member row, or
        // the row-level check would refuse the insert.
        await scope.addWorkspaces([id]);
        await tx.query(
          `INSERT INTO members (workspace_id, account_id, role, created_at)
           VALUES ($1, $2, 'owner', $3)`,
          [id, me, now],
        );
        await writeAudit(tx, now, {
          actorAccountId: me,
          workspaceId: id,
          action: "workspace.create",
          target: id,
        });
        return { kind: "created" as const, id };
      },
    );

    if (outcome.kind === "paused") {
      request.reason = "signup_paused";
      return reply.code(503).send({ error: "unavailable" });
    }
    if (outcome.kind === "too_many") {
      request.reason = "workspace_limit";
      return reply.code(409).send({ error: "workspace_limit" });
    }
    if (outcome.kind === "ceiling") {
      request.reason = "workspace_ceiling";
      return reply.code(503).send({ error: "unavailable" });
    }
    request.reason = "workspace_created";
    return reply.code(201).send({
      id: outcome.id,
      name,
      kind,
      status: "active",
      role: "owner",
    });
  });

  // GET /v1/workspaces: the caller's own.
  app.get("/v1/workspaces", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const rows = await withContext(
      ctx.pool,
      { accountId: session.accountId },
      async (tx) => {
        const found = await tx.query<{
          id: string;
          name: string;
          kind: string;
          status: string;
          role: string;
        }>(
          `SELECT w.id, w.name, w.kind, w.status, m.role
             FROM members m JOIN workspaces w ON w.id = m.workspace_id
            WHERE m.account_id = $1
            ORDER BY w.created_at, w.id`,
          [session.accountId],
        );
        return found.rows;
      },
    );
    const workspaces = rows.filter(
      (row) => isRole(row.role) && can(row.role, "workspace.read"),
    );
    request.reason = "workspaces_listed";
    return reply.code(200).send({ workspaces });
  });

  // GET /v1/workspaces/:id
  app.get("/v1/workspaces/:id", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "workspace.read",
        );
        if (decision.kind !== "ok") return decision;
        const found = await tx.query<{
          id: string;
          name: string;
          kind: string;
          status: string;
        }>("SELECT id, name, kind, status FROM workspaces WHERE id = $1", [id]);
        const row = first(found.rows);
        if (row === undefined) return { kind: "not_found" as const };
        return { kind: "done" as const, row, role: decision.role };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "workspace_read";
    return reply.code(200).send({ ...outcome.row, role: outcome.role });
  });

  // PATCH /v1/workspaces/:id {name}
  app.patch("/v1/workspaces/:id", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const body = request.body;
    const name = isRecord(body) ? parseName(body.name) : null;
    const now = ctx.clock.now();

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "workspace.settings",
        );
        if (decision.kind !== "ok") return decision;
        // Validated after the permission check, so a denied caller learns
        // nothing about the body rules.
        if (name === null) return { kind: "bad_request" as const };
        const updated = await tx.query(
          "UPDATE workspaces SET name = $2 WHERE id = $1",
          [id, name],
        );
        if (updated.rowCount !== 1) return { kind: "not_found" as const };
        await writeAudit(tx, now, {
          actorAccountId: session.accountId,
          workspaceId: id,
          action: "workspace.rename",
          target: id,
        });
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind !== "done") return badRequest(request, reply);
    request.reason = "workspace_renamed";
    return reply.code(200).send({ id, name });
  });

  // DELETE /v1/workspaces/:id (owner only). Members, invitations, limits and
  // keys go by ON DELETE CASCADE.
  app.delete("/v1/workspaces/:id", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const now = ctx.clock.now();

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "workspace.delete",
        );
        if (decision.kind !== "ok") return decision;
        const removed = await tx.query("DELETE FROM workspaces WHERE id = $1", [
          id,
        ]);
        if (removed.rowCount !== 1) return { kind: "not_found" as const };
        await writeAudit(tx, now, {
          actorAccountId: session.accountId,
          workspaceId: id,
          action: "workspace.delete",
          target: id,
        });
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "workspace_deleted";
    return reply.code(204).send();
  });

  // GET /v1/workspaces/:id/members
  app.get("/v1/workspaces/:id/members", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "workspace.read",
        );
        if (decision.kind !== "ok") return decision;
        const found = await tx.query<{ account_id: string; role: string }>(
          `SELECT account_id, role FROM members
            WHERE workspace_id = $1 ORDER BY created_at, account_id`,
          [id],
        );
        return { kind: "done" as const, members: found.rows };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "members_listed";
    return reply.code(200).send({ members: outcome.members });
  });

  // PATCH /v1/workspaces/:id/members/:accountId {role}
  app.patch("/v1/workspaces/:id/members/:accountId", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    const targetId = param(request, "accountId");
    if (id === null || targetId === null) return notFound(request, reply);
    const body = request.body;
    const role: Role | null =
      isRecord(body) && isRole(body.role) && body.role !== "owner"
        ? body.role
        : null;
    const now = ctx.clock.now();

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "member.change_role",
        );
        if (decision.kind !== "ok") return decision;
        // Ownership moves only through the transfer route.
        if (role === null) return { kind: "bad_request" as const };
        const current = await memberRole(tx, id, targetId);
        if (current === null) return { kind: "not_found" as const };
        // Never the owner's role.
        if (current === "owner") return { kind: "owner" as const };
        const updated = await tx.query(
          `UPDATE members SET role = $3
            WHERE workspace_id = $1 AND account_id = $2`,
          [id, targetId, role],
        );
        if (updated.rowCount !== 1) return { kind: "not_found" as const };
        await writeAudit(tx, now, {
          actorAccountId: session.accountId,
          workspaceId: id,
          action: "member.role_change",
          target: targetId,
          reason: role,
        });
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "owner") {
      return forbidden(request, reply, "owner_protected");
    }
    if (outcome.kind !== "done") return badRequest(request, reply);
    request.reason = "member_role_changed";
    return reply.code(200).send({ account_id: targetId, role });
  });

  // DELETE /v1/workspaces/:id/members/:accountId. Never the owner. Any other
  // member may remove themself.
  app.delete(
    "/v1/workspaces/:id/members/:accountId",
    async (request, reply) => {
      const session = await requireSession(ctx, request, reply, {
        allowUnverified: false,
      });
      if (session === null) return reply;
      const id = param(request, "id");
      const targetId = param(request, "accountId");
      if (id === null || targetId === null) return notFound(request, reply);
      const leaving = targetId === session.accountId;
      const now = ctx.clock.now();

      const outcome = await withPathContext(
        ctx.pool,
        { accountId: session.accountId },
        id,
        async (tx) => {
          const decision = await authorize(
            ctx,
            tx,
            session.accountId,
            id,
            leaving ? "workspace.read" : "member.add_remove",
          );
          if (decision.kind !== "ok") return decision;
          const current = await memberRole(tx, id, targetId);
          if (current === null) return { kind: "not_found" as const };
          // The owner cannot leave or be removed: transfer first.
          if (current === "owner") return { kind: "owner" as const };
          const removed = await tx.query(
            "DELETE FROM members WHERE workspace_id = $1 AND account_id = $2",
            [id, targetId],
          );
          if (removed.rowCount !== 1) return { kind: "not_found" as const };
          await writeAudit(tx, now, {
            actorAccountId: session.accountId,
            workspaceId: id,
            action: "member.remove",
            target: targetId,
            reason: leaving ? "left" : "removed",
          });
          return { kind: "done" as const };
        },
      );
      if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
        return deny(request, reply, outcome);
      }
      if (outcome.kind === "owner") {
        return forbidden(request, reply, "owner_protected");
      }
      request.reason = leaving ? "member_left" : "member_removed";
      return reply.code(204).send();
    },
  );

  // POST /v1/workspaces/:id/transfer {accountId} (owner only)
  app.post("/v1/workspaces/:id/transfer", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const body = request.body;
    const targetId =
      isRecord(body) && isUuid(body.accountId) ? body.accountId : null;
    const now = ctx.clock.now();

    const outcome = await withPathContext(
      ctx.pool,
      { accountId: session.accountId },
      id,
      async (tx) => {
        const decision = await authorize(
          ctx,
          tx,
          session.accountId,
          id,
          "workspace.transfer_ownership",
        );
        if (decision.kind !== "ok") return decision;
        if (targetId === null || targetId === session.accountId) {
          return { kind: "bad_request" as const };
        }
        // The target must already be a member.
        if ((await memberRole(tx, id, targetId)) === null) {
          return { kind: "not_found" as const };
        }
        // The target's cap, as for create: lock its account row so a create
        // and a transfer cannot both pass the count.
        const target = await tx.query(
          "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
          [targetId],
        );
        // The target was deleted while this waited for its row.
        if (target.rowCount !== 1) return { kind: "not_found" as const };
        const owned = await tx.query<{ n: number | null }>(
          "SELECT count_owned_workspaces($1) AS n",
          [targetId],
        );
        // A missing count fails closed.
        const ownedCount = first(owned.rows)?.n;
        if (
          ownedCount === undefined ||
          ownedCount === null ||
          ownedCount >= MAX_OWNED_WORKSPACES
        ) {
          return { kind: "too_many" as const };
        }
        // One owner at a time: demote first, then promote.
        await tx.query(
          `UPDATE members SET role = 'admin'
            WHERE workspace_id = $1 AND account_id = $2 AND role = 'owner'`,
          [id, session.accountId],
        );
        const promoted = await tx.query(
          `UPDATE members SET role = 'owner'
            WHERE workspace_id = $1 AND account_id = $2`,
          [id, targetId],
        );
        if (promoted.rowCount !== 1) throw new Error("transfer failed");
        await tx.query("UPDATE workspaces SET owner_id = $2 WHERE id = $1", [
          id,
          targetId,
        ]);
        await writeAudit(tx, now, {
          actorAccountId: session.accountId,
          workspaceId: id,
          action: "workspace.transfer",
          target: targetId,
        });
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "too_many") {
      request.reason = "workspace_limit";
      return reply.code(409).send({ error: "workspace_limit" });
    }
    if (outcome.kind !== "done") return badRequest(request, reply);
    request.reason = "workspace_transferred";
    return reply.code(200).send({ id, owner_id: targetId });
  });
}
