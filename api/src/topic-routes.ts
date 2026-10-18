import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first, withPathContext } from "./db.ts";
import { inFoundWorkspace } from "./found-scope.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid, parseName } from "./input.ts";
import { authorize, badRequest, deny, notFound } from "./workspaces.ts";

function param(request: FastifyRequest, name: string): string | null {
  const params = request.params;
  const value = isRecord(params) ? params[name] : undefined;
  return isUuid(value) ? value : null;
}

export function registerTopicRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/workspaces/:id/topics {name}
  app.post("/v1/workspaces/:id/topics", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const body = request.body;
    const name = isRecord(body) ? parseName(body.name) : null;

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
          "topic.manage",
        );
        if (decision.kind !== "ok") return decision;
        // Validated after the permission check.
        if (name === null) return { kind: "bad_request" as const };
        // The workspace row is locked while topics are counted, so two
        // creates cannot both pass the limit.
        await tx.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [
          id,
        ]);
        const limits = await tx.query<{ max_topics: number }>(
          "SELECT max_topics FROM workspace_limits WHERE workspace_id = $1",
          [id],
        );
        const counted = await tx.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM topics WHERE workspace_id = $1",
          [id],
        );
        const max = first(limits.rows)?.max_topics;
        const n = first(counted.rows)?.n;
        // A missing limit or count fails closed.
        if (max === undefined || n === undefined || n >= max) {
          return { kind: "too_many" as const };
        }
        const made = await tx.query<{ id: string }>(
          `INSERT INTO topics (workspace_id, name) VALUES ($1, $2)
           RETURNING id`,
          [id, name],
        );
        const topicId = first(made.rows)?.id;
        if (topicId === undefined) {
          throw new Error("topic insert returned no row");
        }
        return { kind: "done" as const, topicId };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "too_many") {
      request.reason = "topic_limit";
      return reply.code(409).send({ error: "topic_limit" });
    }
    if (outcome.kind !== "done") return badRequest(request, reply);
    request.reason = "topic_created";
    return reply
      .code(201)
      .send({ id: outcome.topicId, workspace_id: id, name });
  });

  // GET /v1/workspaces/:id/topics
  app.get("/v1/workspaces/:id/topics", async (request, reply) => {
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
          created_at: Date;
        }>(
          `SELECT id, name, created_at FROM topics
            WHERE workspace_id = $1 ORDER BY created_at, id`,
          [id],
        );
        return { kind: "done" as const, topics: found.rows };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "topics_listed";
    return reply.code(200).send({ topics: outcome.topics });
  });

  // PATCH /v1/topics/:id {name}
  app.patch("/v1/topics/:id", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);
    const body = request.body;
    const name = isRecord(body) ? parseName(body.name) : null;

    const outcome = await inFoundWorkspace(
      ctx,
      session.accountId,
      async (tx) => {
        const found = await tx.query<{ workspace_id: string }>(
          "SELECT workspace_id FROM topics WHERE id = $1",
          [id],
        );
        return first(found.rows)?.workspace_id;
      },
      "topic.manage",
      async (tx) => {
        // Validated after the permission check.
        if (name === null) return { kind: "bad_request" as const };
        const updated = await tx.query(
          "UPDATE topics SET name = $2 WHERE id = $1",
          [id, name],
        );
        if (updated.rowCount !== 1) return { kind: "not_found" as const };
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind !== "done") return badRequest(request, reply);
    request.reason = "topic_renamed";
    return reply.code(200).send({ id, name });
  });

  // DELETE /v1/topics/:id. Its keys, subscriptions and messages go by ON
  // DELETE CASCADE.
  app.delete("/v1/topics/:id", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = param(request, "id");
    if (id === null) return notFound(request, reply);

    const outcome = await inFoundWorkspace(
      ctx,
      session.accountId,
      async (tx) => {
        const found = await tx.query<{ workspace_id: string }>(
          "SELECT workspace_id FROM topics WHERE id = $1",
          [id],
        );
        return first(found.rows)?.workspace_id;
      },
      "topic.manage",
      async (tx) => {
        const removed = await tx.query("DELETE FROM topics WHERE id = $1", [
          id,
        ]);
        if (removed.rowCount !== 1) return { kind: "not_found" as const };
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "topic_deleted";
    return reply.code(204).send();
  });
}
