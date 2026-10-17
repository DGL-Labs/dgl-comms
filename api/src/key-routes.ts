import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first, withPathContext } from "./db.ts";
import type { Db } from "./db.ts";
import { inFoundWorkspace } from "./found-scope.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid } from "./input.ts";
import { hashToken, newKeyId, newToken } from "./tokens.ts";
import { authorize, deny, notFound } from "./workspaces.ts";

const KEY_ID = /^pz_[a-z2-7]{8}$/;

function uuidParam(request: FastifyRequest, name: string): string | null {
  const params = request.params;
  const value = isRecord(params) ? params[name] : undefined;
  return isUuid(value) ? value : null;
}

function keyParam(request: FastifyRequest): string | null {
  const params = request.params;
  const value = isRecord(params) ? params.keyId : undefined;
  return typeof value === "string" && KEY_ID.test(value) ? value : null;
}

interface NewKey {
  id: string;
  // The whole credential, pz_<id>.<secret>. Shown once; only the SHA-256 of
  // the secret is stored.
  key: string;
  expiresAt: Date;
}

// Makes a key on a topic, valid for 365 days. Times come from the database
// clock, as resolve_topic_key's do. The caller has authorized and narrowed.
async function insertKey(
  tx: Db,
  topicId: string,
  workspaceId: string,
): Promise<NewKey> {
  // A repeat of a 40-bit id is a one-in-a-trillion event; try a new one.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const id = newKeyId();
    const secret = newToken();
    const made = await tx.query<{ expires_at: Date }>(
      `INSERT INTO topic_keys (id, key_hash, topic_id, workspace_id, expires_at)
       VALUES ($1, $2, $3, $4, now() + interval '365 days')
       ON CONFLICT (id) DO NOTHING
       RETURNING expires_at`,
      [id, hashToken(secret), topicId, workspaceId],
    );
    const row = first(made.rows);
    if (row !== undefined) {
      return { id, key: `${id}.${secret}`, expiresAt: row.expires_at };
    }
  }
  throw new Error("key insert found no free id");
}

export function registerKeyRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/topics/:id/keys. The key is in the reply once and nowhere else.
  app.post("/v1/topics/:id/keys", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const topicId = uuidParam(request, "id");
    if (topicId === null) return notFound(request, reply);

    const outcome = await inFoundWorkspace(
      ctx,
      session.accountId,
      async (tx) => {
        const found = await tx.query<{ workspace_id: string }>(
          "SELECT workspace_id FROM topics WHERE id = $1",
          [topicId],
        );
        return first(found.rows)?.workspace_id;
      },
      "key.manage",
      async (tx, workspaceId) => {
        // authorize has locked the workspace row, so two creates cannot both
        // pass the limit. A rotated, revoked or expired key does not count.
        const limits = await tx.query<{ max_keys: number }>(
          "SELECT max_keys FROM workspace_limits WHERE workspace_id = $1",
          [workspaceId],
        );
        const counted = await tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM topic_keys
            WHERE workspace_id = $1 AND revoked_at IS NULL
              AND rotated_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())`,
          [workspaceId],
        );
        const max = first(limits.rows)?.max_keys;
        const n = first(counted.rows)?.n;
        // A missing limit or count fails closed.
        if (max === undefined || n === undefined || n >= max) {
          return { kind: "too_many" as const };
        }
        const made = await insertKey(tx, topicId, workspaceId);
        return { kind: "done" as const, made };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "too_many") {
      request.reason = "key_limit";
      return reply.code(409).send({ error: "key_limit" });
    }
    request.reason = "key_created";
    return reply
      .header("cache-control", "no-store")
      .code(201)
      .send({
        id: outcome.made.id,
        topic_id: topicId,
        key: outcome.made.key,
        expires_at: outcome.made.expiresAt,
      });
  });

  // GET /v1/workspaces/:id/keys: ids and states, never a hash.
  app.get("/v1/workspaces/:id/keys", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const id = uuidParam(request, "id");
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
          "key.manage",
        );
        if (decision.kind !== "ok") return decision;
        const found = await tx.query<{
          id: string;
          topic_id: string;
          created_at: Date;
          expires_at: Date | null;
          revoked_at: Date | null;
          rotated_at: Date | null;
        }>(
          `SELECT id, topic_id, created_at, expires_at, revoked_at, rotated_at
             FROM topic_keys WHERE workspace_id = $1
            ORDER BY created_at, id`,
          [id],
        );
        return { kind: "done" as const, keys: found.rows };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "keys_listed";
    return reply.code(200).send({ keys: outcome.keys });
  });

  // POST /v1/keys/:keyId/rotate. A new key on the same topic; the old one
  // stays valid for at most 24 hours more. Allowed at the key limit, because
  // the old key stops counting at once.
  app.post("/v1/keys/:keyId/rotate", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const keyId = keyParam(request);
    if (keyId === null) return notFound(request, reply);

    const outcome = await inFoundWorkspace(
      ctx,
      session.accountId,
      async (tx) => {
        const found = await tx.query<{ workspace_id: string }>(
          "SELECT workspace_id FROM topic_keys WHERE id = $1",
          [keyId],
        );
        return first(found.rows)?.workspace_id;
      },
      "key.manage",
      async (tx, workspaceId) => {
        // Read again after authorize has locked the workspace, and lock the
        // key row, so two rotations of one key cannot both succeed.
        const found = await tx.query<{
          topic_id: string;
          usable: boolean;
        }>(
          `SELECT topic_id,
                  (revoked_at IS NULL AND rotated_at IS NULL
                   AND (expires_at IS NULL OR expires_at > now())) AS usable
             FROM topic_keys WHERE id = $1 FOR UPDATE`,
          [keyId],
        );
        const row = first(found.rows);
        if (row === undefined) return { kind: "not_found" as const };
        if (!row.usable) return { kind: "conflict" as const };
        await tx.query(
          `UPDATE topic_keys
              SET rotated_at = now(),
                  expires_at = least(expires_at, now() + interval '24 hours')
            WHERE id = $1`,
          [keyId],
        );
        const made = await insertKey(tx, row.topic_id, workspaceId);
        return { kind: "done" as const, topicId: row.topic_id, made };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    if (outcome.kind === "conflict") {
      request.reason = "key_not_rotatable";
      return reply.code(409).send({ error: "key_not_rotatable" });
    }
    request.reason = "key_rotated";
    return reply
      .header("cache-control", "no-store")
      .code(201)
      .send({
        id: outcome.made.id,
        topic_id: outcome.topicId,
        key: outcome.made.key,
        expires_at: outcome.made.expiresAt,
        rotated_id: keyId,
      });
  });

  // DELETE /v1/keys/:keyId: revoked at once. A repeat keeps the first time.
  app.delete("/v1/keys/:keyId", async (request, reply) => {
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const keyId = keyParam(request);
    if (keyId === null) return notFound(request, reply);

    const outcome = await inFoundWorkspace(
      ctx,
      session.accountId,
      async (tx) => {
        const found = await tx.query<{ workspace_id: string }>(
          "SELECT workspace_id FROM topic_keys WHERE id = $1",
          [keyId],
        );
        return first(found.rows)?.workspace_id;
      },
      "key.manage",
      async (tx) => {
        const revoked = await tx.query(
          `UPDATE topic_keys SET revoked_at = coalesce(revoked_at, now())
            WHERE id = $1`,
          [keyId],
        );
        if (revoked.rowCount !== 1) return { kind: "not_found" as const };
        return { kind: "done" as const };
      },
    );
    if (outcome.kind === "not_found" || outcome.kind === "forbidden") {
      return deny(request, reply, outcome);
    }
    request.reason = "key_revoked";
    return reply.code(204).send();
  });
}
