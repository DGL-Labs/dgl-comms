import type { ServerResponse } from "node:http";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first, withPathContext, withWorkspaceTx } from "./db.ts";
import { inFoundWorkspace } from "./found-scope.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid } from "./input.ts";
import { keyInQuery } from "./publish.ts";
import { deny, notFound } from "./workspaces.ts";

const ROUTE = "/v1/topics/:id/stream";
const REPLAY_MAX = 500;
const KEEPALIVE_MS = 25_000;
const MAX_PER_SESSION = 3;
const MAX_PER_PROCESS = 2000;
const SEQ = /^[0-9]{1,15}$/;

const MESSAGE_COLUMNS =
  "id, topic_id, seq, title, body, sender_label, sender_kind, created_at";

interface MessageRow {
  id: string;
  topic_id: string;
  seq: string;
  title: string | null;
  body: string;
  sender_label: string;
  sender_kind: string;
  created_at: Date;
}

interface Gap {
  from: number;
  to: number;
}

interface Replay {
  gaps: Gap[];
  rows: MessageRow[];
  // The topic's last_seq when the replay was read. Everything up to it is
  // either in rows, covered by a gap, or the client already has it.
  last: number;
}

interface Stream {
  topicId: string;
  // Recorded at access time. A live row is loaded in this workspace's context
  // and never in one that a notification names.
  workspaceId: string;
  res: ServerResponse;
  lastSent: number;
  // Live rows that arrive while the stream opens. Null once the stream is live.
  buffer: MessageRow[] | null;
  started: boolean;
  closed: boolean;
  timer: ReturnType<typeof setInterval> | null;
  end(reason: string): void;
}

type Slot =
  | { kind: "ok"; release(): void }
  | { kind: "session" }
  | { kind: "process" };

export interface StreamHub {
  // The raw payload of a pingzo_msg notification: a hint only.
  notify(payload: string): void;
  // Ends every open stream and refuses nothing new from then on.
  endAll(reason: string): void;
}

function idParam(request: FastifyRequest): string | null {
  const params = request.params;
  const value = isRecord(params) ? params.id : undefined;
  return isUuid(value) ? value : null;
}

function messageFrame(row: MessageRow): string {
  const data = JSON.stringify({
    id: row.id,
    topic_id: row.topic_id,
    seq: Number(row.seq),
    title: row.title,
    body: row.body,
    sender_label: row.sender_label,
    sender_kind: row.sender_kind,
    created_at: row.created_at,
  });
  return `id: ${row.seq}\nevent: message\ndata: ${data}\n\n`;
}

// No id: line, so a gap never moves the client's Last-Event-ID.
function gapFrame(gap: Gap): string {
  return `event: gap\ndata: ${JSON.stringify({ from: gap.from, to: gap.to })}\n\n`;
}

function write(stream: Stream, text: string): void {
  if (stream.closed || stream.res.destroyed || stream.res.writableEnded) return;
  stream.res.write(text);
}

// The drop rule: a seq that was already sent is never sent again.
function sendMessage(stream: Stream, row: MessageRow): void {
  const seq = Number(row.seq);
  if (seq <= stream.lastSent) return;
  stream.lastSent = seq;
  write(stream, messageFrame(row));
}

// One short transaction, under the same context as the access check: the
// caller's memberships cut down to the topic's workspace. It reads the topic's
// counters and what is to be replayed (B1 step 3, B3).
async function readReplay(
  ctx: Ctx,
  accountId: string,
  workspaceId: string,
  topicId: string,
  lastEventId: number | null,
): Promise<Replay | null> {
  return withPathContext(
    ctx.pool,
    { accountId },
    workspaceId,
    async (tx): Promise<Replay | null> => {
      const topic = await tx.query<{
        last_seq: string;
        oldest_kept_seq: string;
      }>("SELECT last_seq, oldest_kept_seq FROM topics WHERE id = $1", [
        topicId,
      ]);
      const row = first(topic.rows);
      if (row === undefined) return null;
      const last = Number(row.last_seq);
      const oldest = Number(row.oldest_kept_seq);
      // Live only: nothing is replayed, and what is already committed is not
      // sent either.
      if (lastEventId === null) return { gaps: [], rows: [], last };

      const gaps: Gap[] = [];
      let start = lastEventId + 1;
      // Messages that were purged.
      if (lastEventId < oldest - 1) {
        gaps.push({ from: start, to: oldest - 1 });
        start = oldest;
      }
      // More missing than one replay carries: the newest 500 are replayed.
      if (last - start + 1 > REPLAY_MAX) {
        gaps.push({ from: start, to: last - REPLAY_MAX });
        start = last - REPLAY_MAX + 1;
      }
      if (start > last) return { gaps, rows: [], last };
      const found = await tx.query<MessageRow>(
        `SELECT ${MESSAGE_COLUMNS} FROM messages
          WHERE topic_id = $1 AND seq >= $2 AND seq <= $3
          ORDER BY seq LIMIT $4`,
        [topicId, start, last, REPLAY_MAX],
      );
      return { gaps, rows: found.rows, last };
    },
  );
}

// GET /v1/topics/:id/stream (server-sent events), for signed-in people only.
// A stream holds no transaction and no pooled connection while it waits: the
// access check, the replay and each live row are short transactions of their
// own. Returns the hub that the LISTEN client feeds.
export function registerStreamRoutes(
  app: FastifyInstance,
  ctx: Ctx,
): StreamHub {
  const byTopic = new Map<string, Set<Stream>>();
  const perSession = new Map<string, number>();
  // Live rows are loaded one after another per topic, so they go out in order.
  const chains = new Map<string, Promise<void>>();
  const keepaliveMs = ctx.streamKeepaliveMs ?? KEEPALIVE_MS;
  const processCap = ctx.streamProcessCap ?? MAX_PER_PROCESS;
  let total = 0;
  let closing = false;

  // Reserved before anything else is awaited, so concurrent opens cannot pass
  // the cap together. Released once, when the stream ends or never opens.
  function reserve(sessionId: string): Slot {
    const mine = perSession.get(sessionId) ?? 0;
    if (mine >= MAX_PER_SESSION) return { kind: "session" };
    if (total >= processCap) return { kind: "process" };
    perSession.set(sessionId, mine + 1);
    total += 1;
    let released = false;
    return {
      kind: "ok",
      release() {
        if (released) return;
        released = true;
        total -= 1;
        const left = (perSession.get(sessionId) ?? 1) - 1;
        if (left <= 0) perSession.delete(sessionId);
        else perSession.set(sessionId, left);
      },
    };
  }

  async function deliver(topicId: string, seq: number): Promise<void> {
    const open = byTopic.get(topicId);
    // The workspace is the one recorded when the stream was opened.
    const workspaceId =
      open === undefined ? undefined : first([...open])?.workspaceId;
    if (workspaceId === undefined) return;
    const found = await withWorkspaceTx(ctx.pool, workspaceId, (tx) =>
      tx.query<MessageRow>(
        `SELECT ${MESSAGE_COLUMNS} FROM messages
          WHERE topic_id = $1 AND seq = $2 AND workspace_id = $3`,
        [topicId, seq, workspaceId],
      ),
    );
    const row = first(found.rows);
    // Not found or not visible: dropped.
    if (row === undefined) return;
    const current = byTopic.get(topicId);
    if (current === undefined) return;
    for (const stream of [...current]) {
      if (stream.closed) continue;
      if (stream.buffer !== null) stream.buffer.push(row);
      else sendMessage(stream, row);
    }
  }

  function notify(payload: string): void {
    if (closing) return;
    const parts = payload.split(":");
    const topicId = parts[0];
    const seqText = parts[1];
    if (
      parts.length !== 2 ||
      !isUuid(topicId) ||
      seqText === undefined ||
      !SEQ.test(seqText)
    ) {
      ctx.logger.log({ event: "stream_notify", reason: "bad_notify" });
      return;
    }
    // No stream on this topic: nothing to do.
    if ((byTopic.get(topicId)?.size ?? 0) === 0) return;
    const seq = Number(seqText);
    const previous = chains.get(topicId) ?? Promise.resolve();
    const next: Promise<void> = previous
      .then(() => deliver(topicId, seq))
      .catch(() => {
        ctx.logger.log({ event: "stream_notify", reason: "load_failed" });
      })
      .then(() => {
        if (chains.get(topicId) === next) chains.delete(topicId);
      });
    chains.set(topicId, next);
  }

  function endAll(reason: string): void {
    closing = true;
    for (const set of [...byTopic.values()]) {
      for (const stream of [...set]) stream.end(reason);
    }
  }

  app.get(ROUTE, async (request, reply) => {
    // A key in the query string is refused, whatever the parameter is called.
    if (keyInQuery(request.query)) {
      request.reason = "key_in_query";
      return reply.code(400).send({ error: "bad_request" });
    }
    // Topic keys do not stream. A key is never resolved: no database call is
    // made for it and nothing is registered.
    const header = request.headers.authorization;
    if (typeof header === "string" && header.startsWith("Bearer pz_")) {
      request.reason = "key_refused";
      return reply.code(401).send({ error: "unauthorized" });
    }
    const session = await requireSession(ctx, request, reply, {
      allowUnverified: false,
    });
    if (session === null) return reply;
    const topicId = idParam(request);
    if (topicId === null) return notFound(request, reply);

    const rawLastEventId = request.headers["last-event-id"];
    let lastEventId: number | null = null;
    if (rawLastEventId !== undefined) {
      if (typeof rawLastEventId !== "string" || !SEQ.test(rawLastEventId)) {
        request.reason = "bad_last_event_id";
        return reply.code(400).send({ error: "bad_request" });
      }
      lastEventId = Number(rawLastEventId);
    }

    const slot = reserve(session.sessionId);
    if (slot.kind !== "ok") {
      request.reason =
        slot.kind === "session"
          ? "stream_limit_session"
          : "stream_limit_process";
      return reply
        .header("retry-after", "5")
        .code(429)
        .send({ error: "stream_limit" });
    }

    const res = reply.raw;
    const client = { gone: false };
    let stream: Stream | null = null;
    res.once("close", () => {
      client.gone = true;
      if (stream !== null) stream.end("client_closed");
    });

    try {
      // Step 1: access. A short transaction that returns the workspace id.
      const access = await inFoundWorkspace(
        ctx,
        session.accountId,
        async (tx) => {
          const found = await tx.query<{ workspace_id: string }>(
            "SELECT workspace_id FROM topics WHERE id = $1",
            [topicId],
          );
          return first(found.rows)?.workspace_id;
        },
        "workspace.read",
        async (_tx, workspaceId) => ({ kind: "ok" as const, workspaceId }),
      );
      if (access.kind === "not_found" || access.kind === "forbidden") {
        return deny(request, reply, access);
      }
      if (client.gone || closing) {
        reply.hijack();
        return reply;
      }

      // Step 2: register. Live rows are buffered from here on.
      const opened = Date.now();
      const made: Stream = {
        topicId,
        workspaceId: access.workspaceId,
        res,
        lastSent: 0,
        buffer: [],
        started: false,
        closed: false,
        timer: null,
        end(reason) {
          if (made.closed) return;
          made.closed = true;
          if (made.timer !== null) clearInterval(made.timer);
          const set = byTopic.get(topicId);
          if (set !== undefined) {
            set.delete(made);
            if (set.size === 0) byTopic.delete(topicId);
          }
          slot.release();
          // Before the headers went out, the route's own reply speaks.
          if (!made.started) return;
          if (!res.writableEnded) res.end();
          ctx.logger.log({
            event: "stream_end",
            request_id: request.id,
            route: ROUTE,
            status: 200,
            latency_ms: Date.now() - opened,
            account_id: session.accountId,
            reason,
          });
        },
      };
      stream = made;
      const siblings = byTopic.get(topicId) ?? new Set<Stream>();
      siblings.add(made);
      byTopic.set(topicId, siblings);

      // Step 3: replay, read under the same context as step 1.
      const replay = await readReplay(
        ctx,
        session.accountId,
        access.workspaceId,
        topicId,
        lastEventId,
      );
      if (made.closed) {
        reply.hijack();
        return reply;
      }
      if (replay === null) {
        made.end("not_found");
        return notFound(request, reply);
      }

      // Step 4: send the replay.
      reply.hijack();
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        "x-accel-buffering": "no",
      });
      res.flushHeaders();
      made.started = true;
      ctx.logger.log({
        event: "stream_open",
        request_id: request.id,
        route: ROUTE,
        status: 200,
        account_id: session.accountId,
        reason: "opened",
      });
      for (const gap of replay.gaps) write(made, gapFrame(gap));
      for (const row of replay.rows) write(made, messageFrame(row));
      made.lastSent = replay.last;

      // Step 5: flush the buffer, dropping any seq already sent. No await
      // between this and going live, so nothing slips in between.
      const buffered = made.buffer ?? [];
      made.buffer = null;
      buffered.sort((a, b) => Number(a.seq) - Number(b.seq));
      for (const row of buffered) sendMessage(made, row);

      // Step 6: live.
      made.timer = setInterval(
        () => write(made, ": keepalive\n\n"),
        keepaliveMs,
      );
      return reply;
    } catch (error) {
      if (stream !== null) stream.end("error");
      throw error;
    } finally {
      if (stream === null) slot.release();
    }
  });

  return { notify, endAll };
}
