import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { clientIp } from "./context.ts";
import type { Ctx } from "./context.ts";
import {
  takeCallerToken,
  takeDailyMessage,
  takeGlobalMessage,
  takeWorkspaceToken,
} from "./counters.ts";
import {
  first,
  holdTx,
  setLockTimeout,
  withContext,
  withKeyContext,
  withPathContext,
} from "./db.ts";
import type { Db } from "./db.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid } from "./input.ts";
import { can } from "./permissions.ts";
import { hashToken } from "./tokens.ts";
import { deny, forbidden, memberRole, notFound } from "./workspaces.ts";

const MAX_TITLE_CHARS = 120;
// A key is accepted only here: pz_<8>.<secret, 32 bytes base64url>.
const KEY_HEADER = /^Bearer (pz_[a-z2-7]{8})\.([A-Za-z0-9_-]{43})$/;
const KEY_LIKE = /pz_[a-z2-7]{8}/i;
const KEY_PARAMS = new Set([
  "key",
  "api_key",
  "apikey",
  "access_token",
  "token",
  "auth",
  "authorization",
]);
const IDEMPOTENCY_KEY = /^[\x20-\x7e]{1,200}$/;

type Caller =
  | { kind: "session"; accountId: string }
  | { kind: "key"; keyId: string; secretHash: Buffer };

type Preflight =
  | {
      kind: "ok";
      workspaceId: string;
      workspaceKind: string;
      perMinute: number;
      perDay: number;
    }
  | { kind: "not_found" }
  | { kind: "forbidden" }
  | { kind: "unauthorized" }
  | { kind: "unavailable" };

type Published =
  | { kind: "done"; id: string; seq: number; replay: boolean }
  | { kind: "not_found" }
  | { kind: "forbidden" }
  | { kind: "unauthorized" }
  | { kind: "unavailable" }
  | { kind: "paused" }
  | { kind: "bad_request" }
  | { kind: "too_large" }
  | { kind: "idempotency_conflict" }
  | { kind: "busy" };

// Ends the main transaction with a rollback and an outcome: used once the
// idempotency row is claimed, so that nothing of a refused publish is kept.
class Stop extends Error {
  outcome: Published;

  constructor(outcome: Published) {
    super("stop");
    this.outcome = outcome;
  }
}

function pgCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error.code === "string"
    ? error.code
    : undefined;
}

function hasControl(s: string): boolean {
  return [...s].some((c) => {
    const code = c.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
}

function topicParam(request: FastifyRequest): string | null {
  const params = request.params;
  const value = isRecord(params) ? params.id : undefined;
  return isUuid(value) ? value : null;
}

// A key in the query string is refused, whatever the parameter is called.
export function keyInQuery(query: unknown): boolean {
  if (!isRecord(query)) return false;
  return Object.entries(query).some(
    ([name, value]) =>
      KEY_PARAMS.has(name.toLowerCase()) ||
      KEY_LIKE.test(name) ||
      KEY_LIKE.test(JSON.stringify(value)),
  );
}

// The decision for message.post, without the workspace row lock that
// authorize takes: publishes to different topics of one workspace must not
// wait on each other. Row-level security shows only memberships of the
// caller's own workspaces, so another workspace gives not_found.
async function mayPost(
  ctx: Ctx,
  tx: Db,
  accountId: string,
  workspaceId: string,
): Promise<"ok" | "not_found" | "forbidden"> {
  // Test hook only (AppDeps.testHooks). It is never set from config.
  if (ctx.skipPermissionChecks) return "ok";
  const role = await memberRole(tx, workspaceId, accountId);
  if (role === null) return "not_found";
  return can(role, "message.post") ? "ok" : "forbidden";
}

// The workspace's kind and its two rate limits. Any missing row fails closed.
async function readWorkspace(tx: Db, workspaceId: string): Promise<Preflight> {
  const found = await tx.query<{
    kind: string;
    msgs_per_day: number;
    msgs_per_min: number;
  }>(
    `SELECT w.kind, l.msgs_per_day, l.msgs_per_min
       FROM workspaces w JOIN workspace_limits l ON l.workspace_id = w.id
      WHERE w.id = $1`,
    [workspaceId],
  );
  const row = first(found.rows);
  if (row === undefined) return { kind: "unavailable" };
  return {
    kind: "ok",
    workspaceId,
    workspaceKind: row.kind,
    perMinute: row.msgs_per_min,
    perDay: row.msgs_per_day,
  };
}

// Step 2: a short transaction. Resolves the caller and authorizes message.post
// (a key only on its own topic). It yields the workspace id and kind. A caller
// that is not authorized stops here.
async function preflight(
  ctx: Ctx,
  caller: Caller,
  topicId: string,
): Promise<Preflight> {
  if (caller.kind === "key") {
    const done = await withKeyContext(
      ctx.pool,
      caller.keyId,
      caller.secretHash,
      async (tx, key): Promise<Preflight> => {
        if (key.topicId !== topicId) return { kind: "not_found" };
        return readWorkspace(tx, key.workspaceId);
      },
    );
    return done ?? { kind: "unauthorized" };
  }
  return withContext(
    ctx.pool,
    { accountId: caller.accountId },
    async (tx, scope): Promise<Preflight> => {
      const found = await tx.query<{ workspace_id: string }>(
        "SELECT workspace_id FROM topics WHERE id = $1",
        [topicId],
      );
      const workspaceId = first(found.rows)?.workspace_id;
      if (workspaceId === undefined) return { kind: "not_found" };
      const verdict = await mayPost(ctx, tx, caller.accountId, workspaceId);
      if (verdict !== "ok") return { kind: verdict };
      await scope.narrowTo(workspaceId);
      return readWorkspace(tx, workspaceId);
    },
  );
}

type Parsed =
  | { kind: "ok"; title: string | null; body: string }
  | { kind: "bad_request" }
  | { kind: "too_large" };

// Body in UTF-8 bytes (not characters), title in characters. NUL cannot be
// stored in text, and a title is one line.
function parseMessage(raw: unknown, maxBytes: number): Parsed {
  if (!isRecord(raw)) return { kind: "bad_request" };
  const { title, body } = raw;
  if (typeof body !== "string" || body === "" || body.includes("\u0000")) {
    return { kind: "bad_request" };
  }
  let cleanTitle: string | null = null;
  if (title !== undefined && title !== null) {
    if (
      typeof title !== "string" ||
      [...title].length > MAX_TITLE_CHARS ||
      hasControl(title)
    ) {
      return { kind: "bad_request" };
    }
    cleanTitle = title === "" ? null : title;
  }
  if (Buffer.byteLength(body, "utf8") > maxBytes) return { kind: "too_large" };
  return { kind: "ok", title: cleanTitle, body };
}

interface PublishInput {
  topicId: string;
  workspaceId: string;
  rawBody: unknown;
  rawIdempotency: unknown;
}

// Step 4, inside the transaction and its context: authorize again, the pause
// flag, the size checks, idempotency, then seq, message, job and notify.
async function publishIn(
  ctx: Ctx,
  tx: Db,
  caller: Caller,
  input: PublishInput,
): Promise<Published> {
  const { topicId, workspaceId } = input;
  if (ctx.lockTimeoutMs !== null) await setLockTimeout(tx, ctx.lockTimeoutMs);

  if (caller.kind === "session") {
    const verdict = await mayPost(ctx, tx, caller.accountId, workspaceId);
    if (verdict !== "ok") return { kind: verdict };
  }

  const flags = await tx.query<{
    kind: string;
    max_body_bytes: number;
    paused: boolean;
  }>(
    `SELECT w.kind, l.max_body_bytes,
            s.publish_paused_non_internal AS paused
       FROM workspaces w
       JOIN workspace_limits l ON l.workspace_id = w.id
       CROSS JOIN service_limits s
      WHERE w.id = $1`,
    [workspaceId],
  );
  const row = first(flags.rows);
  if (row === undefined) return { kind: "unavailable" };
  if (row.kind !== "dgl_internal" && row.paused !== false) {
    return { kind: "paused" };
  }

  const parsed = parseMessage(input.rawBody, row.max_body_bytes);
  if (parsed.kind !== "ok") return parsed;
  const header = input.rawIdempotency;
  let idempotencyKey: string | null = null;
  if (header !== undefined) {
    if (typeof header !== "string" || !IDEMPOTENCY_KEY.test(header)) {
      return { kind: "bad_request" };
    }
    idempotencyKey = header;
  }
  const who =
    caller.kind === "session" ? `a:${caller.accountId}` : `k:${caller.keyId}`;

  if (idempotencyKey !== null) {
    // A row older than 24 hours is taken over. A concurrent duplicate waits
    // here for the first attempt to commit or roll back.
    let claimed;
    try {
      claimed = await tx.query(
        `INSERT INTO idempotency_keys (caller, key, workspace_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (caller, key) DO UPDATE
           SET workspace_id = EXCLUDED.workspace_id, message_id = NULL,
               created_at = now()
         WHERE idempotency_keys.created_at < now() - interval '24 hours'
         RETURNING caller`,
        [who, idempotencyKey, workspaceId],
      );
    } catch (error) {
      // The conflicting row belongs to another workspace: row-level security
      // refuses to show it to the update. Never a 500 or a retry loop.
      if (pgCode(error) === "42501") {
        throw new Stop({ kind: "idempotency_conflict" });
      }
      throw error;
    }
    if (first(claimed.rows) === undefined) {
      const existing = await tx.query<{ message_id: string | null }>(
        `SELECT message_id FROM idempotency_keys
          WHERE caller = $1 AND key = $2 FOR SHARE`,
        [who, idempotencyKey],
      );
      const messageId = first(existing.rows)?.message_id;
      // No visible row, or no result recorded: a conflict.
      if (messageId === undefined || messageId === null) {
        throw new Stop({ kind: "idempotency_conflict" });
      }
      const earlier = await tx.query<{
        id: string;
        topic_id: string;
        seq: string;
      }>("SELECT id, topic_id, seq FROM messages WHERE id = $1", [messageId]);
      const message = first(earlier.rows);
      // The same caller and key for another topic is a conflict too.
      if (message === undefined || message.topic_id !== topicId) {
        throw new Stop({ kind: "idempotency_conflict" });
      }
      return {
        kind: "done",
        id: message.id,
        seq: Number(message.seq),
        replay: true,
      };
    }
  }

  // The topic row lock taken here is the only lock a publish waits on.
  const bumped = await tx.query<{ last_seq: string }>(
    `UPDATE topics SET last_seq = last_seq + 1
      WHERE id = $1 AND workspace_id = $2 RETURNING last_seq`,
    [topicId, workspaceId],
  );
  const seq = first(bumped.rows)?.last_seq;
  if (seq === undefined) throw new Stop({ kind: "not_found" });

  // Test hook only (AppDeps.testHooks): hold the transaction after the seq.
  if (ctx.holdAfterSeqMs !== null) await holdTx(tx, ctx.holdAfterSeqMs);

  const sender =
    caller.kind === "session"
      ? { accountId: caller.accountId, keyId: null, label: "Member" }
      : { accountId: null, keyId: caller.keyId, label: caller.keyId };
  const made = await tx.query<{ id: string }>(
    `INSERT INTO messages
       (topic_id, workspace_id, seq, sender_account_id, sender_key_id,
        sender_label, sender_kind, title, body)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [
      topicId,
      workspaceId,
      seq,
      sender.accountId,
      sender.keyId,
      sender.label,
      caller.kind === "session" ? "person" : "key",
      parsed.title,
      parsed.body,
    ],
  );
  const id = first(made.rows)?.id;
  if (id === undefined) throw new Error("message insert returned no row");
  await tx.query(
    "INSERT INTO fanout_jobs (message_id, workspace_id) VALUES ($1, $2)",
    [id, workspaceId],
  );
  if (idempotencyKey !== null) {
    await tx.query(
      `UPDATE idempotency_keys SET message_id = $3
        WHERE caller = $1 AND key = $2`,
      [who, idempotencyKey, id],
    );
  }
  // Ids only; delivered when the transaction commits.
  await tx.query("SELECT pg_notify('pingzo_msg', $1)", [`${topicId}:${seq}`]);
  return { kind: "done", id, seq: Number(seq), replay: false };
}

async function mainTransaction(
  ctx: Ctx,
  caller: Caller,
  topicId: string,
  workspaceId: string,
  request: FastifyRequest,
): Promise<Published> {
  const input = {
    topicId,
    workspaceId,
    rawBody: request.body,
    rawIdempotency: request.headers["idempotency-key"],
  };
  try {
    if (caller.kind === "key") {
      // resolve_topic_key is the only statement before the context.
      const done = await withKeyContext(
        ctx.pool,
        caller.keyId,
        caller.secretHash,
        async (tx, key): Promise<Published> => {
          if (key.topicId !== topicId) return { kind: "not_found" };
          return publishIn(ctx, tx, caller, {
            ...input,
            workspaceId: key.workspaceId,
          });
        },
      );
      return done ?? { kind: "unauthorized" };
    }
    return await withPathContext(
      ctx.pool,
      { accountId: caller.accountId },
      workspaceId,
      (tx) => publishIn(ctx, tx, caller, input),
    );
  } catch (error) {
    if (error instanceof Stop) return error.outcome;
    // A lock wait over lock_timeout: retryable.
    if (pgCode(error) === "55P03") return { kind: "busy" };
    throw error;
  }
}

function limited(
  request: FastifyRequest,
  reply: FastifyReply,
  reason: string,
  error: string,
) {
  request.reason = reason;
  return reply.header("retry-after", "60").code(429).send({ error });
}

export function registerPublishRoutes(app: FastifyInstance, ctx: Ctx): void {
  // POST /v1/topics/:id/messages {title?, body}, by session or by key.
  app.post("/v1/topics/:id/messages", async (request, reply) => {
    if (keyInQuery(request.query)) {
      request.reason = "key_in_query";
      return reply.code(400).send({ error: "bad_request" });
    }

    // Step 1: the caller bucket, first and in its own statement. A key caller
    // is charged to its IP for every attempt, good or bad; a session caller
    // is known only after its session check, then charged to its account.
    let caller: Caller;
    const header = request.headers.authorization;
    if (typeof header === "string" && header.startsWith("Bearer pz_")) {
      const bucket = `ip:${clientIp(ctx, request)}`;
      if (!(await takeCallerToken(ctx.pool, bucket))) {
        return limited(request, reply, "caller_rate_limited", "rate_limited");
      }
      const parsed = KEY_HEADER.exec(header);
      const keyId = parsed?.[1];
      const secret = parsed?.[2];
      if (keyId === undefined || secret === undefined) {
        request.reason = "key_invalid";
        return reply.code(401).send({ error: "unauthorized" });
      }
      caller = { kind: "key", keyId, secretHash: hashToken(secret) };
    } else {
      const session = await requireSession(ctx, request, reply, {
        allowUnverified: false,
      });
      if (session === null) return reply;
      if (!(await takeCallerToken(ctx.pool, `acct:${session.accountId}`))) {
        return limited(request, reply, "caller_rate_limited", "rate_limited");
      }
      caller = { kind: "session", accountId: session.accountId };
    }

    const topicId = topicParam(request);
    if (topicId === null) return notFound(request, reply);

    // Step 2: preflight. Charged to the caller bucket only.
    const pre = await preflight(ctx, caller, topicId);
    if (pre.kind === "unauthorized") {
      request.reason = "key_invalid";
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (pre.kind === "not_found") return notFound(request, reply);
    if (pre.kind === "forbidden") return forbidden(request, reply);
    if (pre.kind === "unavailable") {
      request.reason = "limits_missing";
      return reply.code(503).send({ error: "unavailable" });
    }

    // Step 3: the workspace and global debits, each in its own statement.
    if (!(await takeWorkspaceToken(ctx.pool, pre.workspaceId, pre.perMinute))) {
      return limited(
        request,
        reply,
        "workspace_rate_limited",
        "workspace_rate_limited",
      );
    }
    if (!(await takeDailyMessage(ctx.pool, pre.workspaceId, pre.perDay))) {
      request.reason = "daily_limit";
      return reply.code(429).send({ error: "daily_limit" });
    }
    if (
      pre.workspaceKind !== "dgl_internal" &&
      !(await takeGlobalMessage(ctx.pool))
    ) {
      request.reason = "global_ceiling";
      return reply.code(503).send({ error: "ceiling" });
    }

    // Steps 4 and 5: the main transaction.
    const outcome = await mainTransaction(
      ctx,
      caller,
      topicId,
      pre.workspaceId,
      request,
    );
    switch (outcome.kind) {
      case "done":
        request.reason = outcome.replay ? "publish_replayed" : "published";
        return reply
          .header("cache-control", "no-store")
          .code(201)
          .send({ id: outcome.id, topic_id: topicId, seq: outcome.seq });
      case "not_found":
      case "forbidden":
        return deny(request, reply, outcome);
      case "unauthorized":
        request.reason = "key_invalid";
        return reply.code(401).send({ error: "unauthorized" });
      case "unavailable":
        request.reason = "limits_missing";
        return reply.code(503).send({ error: "unavailable" });
      case "paused":
        request.reason = "publish_paused";
        return reply.code(503).send({ error: "unavailable" });
      case "bad_request":
        request.reason = "bad_request";
        return reply.code(400).send({ error: "bad_request" });
      case "too_large":
        request.reason = "body_too_large";
        return reply.code(413).send({ error: "body_too_large" });
      case "idempotency_conflict":
        request.reason = "idempotency_conflict";
        return reply.code(409).send({ error: "idempotency_conflict" });
      case "busy":
        request.reason = "busy";
        return reply
          .header("retry-after", "1")
          .code(503)
          .send({ error: "busy" });
    }
  });
}
