import type { ServerResponse } from "node:http";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first, withPathContext, withWorkspaceTx } from "./db.ts";
import { inFoundWorkspace } from "./found-scope.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid } from "./input.ts";
import { can } from "./permissions.ts";
import { keyInQuery } from "./publish.ts";
import { deny, memberRole, notFound } from "./workspaces.ts";

const ROUTE = "/v1/topics/:id/stream";
const REPLAY_MAX = 500;
const KEEPALIVE_MS = 25_000;
// Every open stream re-checks its access this often, so a revocation holds
// while LISTEN is down.
const RECHECK_MS = 60_000;
// While LISTEN is down, each topic with open streams is polled this often.
const POLL_MS = 5_000;
// Reasons that the client is told about, with event: end.
const END_EVENT_REASONS: ReadonlySet<string> = new Set([
  "revoked",
  "token_expired",
  "server_closing",
]);
const MAX_PER_SESSION = 3;
const MAX_PER_PROCESS = 2000;
const SEQ = /^[0-9]{1,15}$/;

const MESSAGE_COLUMNS =
  "id, topic_id, seq, title, body, sender_label, sender_kind, created_at";

export interface MessageRow {
  id: string;
  topic_id: string;
  seq: string;
  title: string | null;
  body: string;
  sender_label: string;
  sender_kind: string;
  created_at: Date;
}

export interface Gap {
  from: number;
  to: number;
}

export interface Replay {
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
  accountId: string;
  sessionId: string;
  // When the access token that opened the stream expires.
  expiresAt: Date;
  res: ServerResponse;
  lastSent: number;
  // Live rows that arrive while the stream opens. Null once the stream is live.
  buffer: MessageRow[] | null;
  started: boolean;
  closed: boolean;
  timer: ReturnType<typeof setInterval> | null;
  recheckTimer: ReturnType<typeof setInterval> | null;
  expiryTimer: ReturnType<typeof setTimeout> | null;
  // An access re-check is waiting in the queue.
  queued: boolean;
  // A hint named this stream before it went live: re-check as soon as it does.
  hinted: boolean;
  end(reason: string): void;
}

export type Slot =
  | { kind: "ok"; release(): void }
  | { kind: "session" }
  | { kind: "process" };

export interface StreamHub {
  // The raw payload of a pingzo_msg notification: a hint only.
  notify(payload: string): void;
  // The raw payload of a pingzo_acl notification: a hint only. It selects the
  // streams to re-check and closes none by itself.
  aclNotify(payload: string): void;
  // The LISTEN connection went down: poll the topics with open streams.
  listenDown(): void;
  // The LISTEN connection is back: stop polling, catch each topic up once.
  listenUp(): void;
  // Ends every open stream and refuses nothing new from then on.
  endAll(reason: string): void;
  // Takes one of the caller's slots (3 per session, 2,000 per process). The
  // long-poll route (B6) counts against the same slots.
  reserve(sessionId: string): Slot;
}

function idParam(request: FastifyRequest): string | null {
  const params = request.params;
  const value = isRecord(params) ? params.id : undefined;
  return isUuid(value) ? value : null;
}

// A message as a client sees it, on the stream and from the long-poll route.
export function messageData(row: MessageRow) {
  return {
    id: row.id,
    topic_id: row.topic_id,
    seq: Number(row.seq),
    title: row.title,
    body: row.body,
    sender_label: row.sender_label,
    sender_kind: row.sender_kind,
    created_at: row.created_at,
  };
}

function messageFrame(row: MessageRow): string {
  const data = JSON.stringify(messageData(row));
  return `id: ${row.seq}\nevent: message\ndata: ${data}\n\n`;
}

// No id: line, so a gap never moves the client's Last-Event-ID.
function gapFrame(gap: Gap): string {
  return `event: gap\ndata: ${JSON.stringify({ from: gap.from, to: gap.to })}\n\n`;
}

// The last frame of a stream that the server ends. No id: line either.
function endFrame(reason: string): string {
  return `event: end\ndata: ${JSON.stringify({ reason })}\n\n`;
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
export async function readReplay(
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

// The access check of a new stream or long-poll (B1 step 1), in one short
// transaction: the caller's membership with workspace.read, found and narrowed
// by inFoundWorkspace. A suspended workspace looks like no topic (PC ruling
// 1143). Returns the topic's workspace id.
export function streamAccess(ctx: Ctx, accountId: string, topicId: string) {
  return inFoundWorkspace(
    ctx,
    accountId,
    async (tx) => {
      const found = await tx.query<{ workspace_id: string }>(
        "SELECT workspace_id FROM topics WHERE id = $1",
        [topicId],
      );
      return first(found.rows)?.workspace_id;
    },
    "workspace.read",
    async (tx, workspaceId) => {
      const workspace = await tx.query<{ status: string }>(
        "SELECT status FROM workspaces WHERE id = $1",
        [workspaceId],
      );
      if (first(workspace.rows)?.status !== "active") {
        return { kind: "not_found" as const };
      }
      return { kind: "ok" as const, workspaceId };
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
  const sessionCap = ctx.streamSessionCap ?? MAX_PER_SESSION;
  const recheckMs = ctx.streamRecheckMs ?? RECHECK_MS;
  const pollMs = ctx.streamPollMs ?? POLL_MS;
  // Access re-checks run one after another, so a revocation that touches
  // thousands of streams uses one pooled connection at a time.
  let recheckChain: Promise<void> = Promise.resolve();
  // Topics with a catch-up waiting in their chain.
  const catchingUp = new Set<string>();
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let listenIsDown = false;
  let total = 0;
  let closing = false;

  // Reserved before anything else is awaited, so concurrent opens cannot pass
  // the cap together. Released once, when the stream ends or never opens.
  function reserve(sessionId: string): Slot {
    const mine = perSession.get(sessionId) ?? 0;
    if (mine >= sessionCap) return { kind: "session" };
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
    // A live stream that is missing a seq before this one (a notification was
    // lost around a LISTEN outage) is brought up to date by reading from its
    // own last seq, so that sending this one alone cannot skip the rest.
    const behind = [...current].some(
      (stream) =>
        !stream.closed && stream.buffer === null && stream.lastSent + 1 < seq,
    );
    if (behind) {
      await catchUp(topicId);
      return;
    }
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
    enqueue(topicId, () => deliver(topicId, seq));
  }

  // Everything that reads rows for a topic's streams (a live row, a poll, a
  // catch-up) runs in that topic's chain, one job after another.
  function enqueue(topicId: string, job: () => Promise<void>): void {
    const previous = chains.get(topicId) ?? Promise.resolve();
    const next: Promise<void> = previous
      .then(job)
      .catch(() => {
        ctx.logger.log({ event: "stream_notify", reason: "load_failed" });
      })
      .then(() => {
        if (chains.get(topicId) === next) chains.delete(topicId);
      });
    chains.set(topicId, next);
  }

  // Reads what the topic's live streams have not got yet, at most 500 rows per
  // query, in the workspace recorded on the streams, and drains until a query
  // comes back short. Each row goes through the same drop-any-seq-already-sent
  // rule. A stream behind oldest_kept_seq gets the B3 gap event first.
  async function catchUp(topicId: string): Promise<void> {
    let previousLowest = -1;
    for (;;) {
      const open = byTopic.get(topicId);
      if (open === undefined) return;
      const live = [...open].filter(
        (stream) => !stream.closed && stream.buffer === null,
      );
      const lead = first(live);
      if (lead === undefined) return;
      const workspaceId = lead.workspaceId;
      const lowest = Math.min(...live.map((stream) => stream.lastSent));
      // No progress since the last query: stop rather than loop.
      if (lowest <= previousLowest) return;
      previousLowest = lowest;
      const got = await withWorkspaceTx(ctx.pool, workspaceId, async (tx) => {
        const topic = await tx.query<{ oldest_kept_seq: string }>(
          `SELECT oldest_kept_seq FROM topics
            WHERE id = $1 AND workspace_id = $2`,
          [topicId, workspaceId],
        );
        const row = first(topic.rows);
        if (row === undefined) return null;
        const oldest = Number(row.oldest_kept_seq);
        const found = await tx.query<MessageRow>(
          `SELECT ${MESSAGE_COLUMNS} FROM messages
            WHERE topic_id = $1 AND workspace_id = $2 AND seq > $3
            ORDER BY seq LIMIT $4`,
          [topicId, workspaceId, Math.max(lowest, oldest - 1), REPLAY_MAX],
        );
        return { oldest, rows: found.rows };
      });
      if (got === null) return;
      const current = byTopic.get(topicId);
      if (current === undefined) return;
      for (const stream of [...current]) {
        if (stream.closed) continue;
        if (stream.buffer !== null) {
          stream.buffer.push(...got.rows);
          continue;
        }
        if (stream.lastSent < got.oldest - 1) {
          write(
            stream,
            gapFrame({ from: stream.lastSent + 1, to: got.oldest - 1 }),
          );
          stream.lastSent = got.oldest - 1;
        }
        for (const row of got.rows) sendMessage(stream, row);
      }
      if (got.rows.length < REPLAY_MAX) return;
    }
  }

  function scheduleCatchUp(topicId: string): void {
    if (catchingUp.has(topicId)) return;
    catchingUp.add(topicId);
    enqueue(topicId, async () => {
      catchingUp.delete(topicId);
      await catchUp(topicId);
    });
  }

  function pollAll(): void {
    for (const topicId of [...byTopic.keys()]) scheduleCatchUp(topicId);
  }

  function stopPolling(): void {
    if (pollTimer !== null) clearInterval(pollTimer);
    pollTimer = null;
  }

  function listenDown(): void {
    if (closing || listenIsDown) return;
    listenIsDown = true;
    // At once, for what was published before the loss was noticed, then every
    // poll interval until LISTEN is back.
    pollAll();
    pollTimer = setInterval(pollAll, pollMs);
  }

  function listenUp(): void {
    if (closing) return;
    listenIsDown = false;
    stopPolling();
    // What was published while LISTEN was down: once per topic, in its chain.
    pollAll();
  }

  // The access check of a stream that is already open, in one short
  // transaction. Everything must still hold: the session (as requireSession
  // checks it), the membership with workspace.read, the topic, and an active
  // workspace. Anything missing is a no.
  async function stillAllowed(stream: Stream): Promise<boolean> {
    return withPathContext(
      ctx.pool,
      { accountId: stream.accountId },
      stream.workspaceId,
      async (tx) => {
        const session = await tx.query(
          `SELECT s.id
             FROM sessions s JOIN accounts a ON a.id = s.account_id
            WHERE s.id = $1 AND s.account_id = $2
              AND s.revoked_at IS NULL AND s.expires_at > $3
              AND a.status = 'active'`,
          [stream.sessionId, stream.accountId, ctx.clock.now()],
        );
        if (first(session.rows) === undefined) return false;
        const role = await memberRole(tx, stream.workspaceId, stream.accountId);
        if (role === null || !can(role, "workspace.read")) return false;
        const topic = await tx.query(
          "SELECT id FROM topics WHERE id = $1 AND workspace_id = $2",
          [stream.topicId, stream.workspaceId],
        );
        if (first(topic.rows) === undefined) return false;
        const workspace = await tx.query<{ status: string }>(
          "SELECT status FROM workspaces WHERE id = $1",
          [stream.workspaceId],
        );
        return first(workspace.rows)?.status === "active";
      },
    );
  }

  // Ends the stream if its access token has run out, by the app's clock.
  function expireIfDue(stream: Stream): boolean {
    if (stream.closed) return true;
    if (ctx.clock.now().getTime() < stream.expiresAt.getTime()) return false;
    stream.end("token_expired");
    return true;
  }

  function armExpiry(stream: Stream): void {
    const left = stream.expiresAt.getTime() - ctx.clock.now().getTime();
    const wait = Math.max(left, 1000);
    stream.expiryTimer = setTimeout(() => {
      if (!expireIfDue(stream)) armExpiry(stream);
    }, wait);
  }

  // Queues an access re-check. The stream closes only if the check says no. A
  // database error is not a no: the stream stays and the next re-check (a hint
  // or the interval) tries again.
  function queueRecheck(stream: Stream): void {
    if (stream.closed) return;
    if (!stream.started) {
      stream.hinted = true;
      return;
    }
    if (stream.queued) return;
    stream.queued = true;
    recheckChain = recheckChain.then(async () => {
      stream.queued = false;
      if (stream.closed || expireIfDue(stream)) return;
      try {
        if (!(await stillAllowed(stream))) stream.end("revoked");
      } catch {
        ctx.logger.log({ event: "stream_recheck", reason: "recheck_failed" });
      }
    });
  }

  function aclNotify(payload: string): void {
    if (closing) return;
    const parts = payload.split(":");
    const kind = parts[0];
    const a = parts[1];
    const b = parts[2];
    let match: ((stream: Stream) => boolean) | null = null;
    if (kind === "member" && parts.length === 3 && isUuid(a) && isUuid(b)) {
      match = (stream) => stream.workspaceId === a && stream.accountId === b;
    } else if (kind === "session" && parts.length === 2 && isUuid(a)) {
      match = (stream) => stream.sessionId === a;
    } else if (kind === "account" && parts.length === 2 && isUuid(a)) {
      match = (stream) => stream.accountId === a;
    } else if (kind === "topic" && parts.length === 2 && isUuid(a)) {
      match = (stream) => stream.topicId === a;
    } else if (kind === "workspace" && parts.length === 2 && isUuid(a)) {
      match = (stream) => stream.workspaceId === a;
    }
    if (match === null) {
      ctx.logger.log({ event: "stream_acl", reason: "bad_notify" });
      return;
    }
    for (const set of [...byTopic.values()]) {
      for (const stream of [...set]) {
        if (match(stream)) queueRecheck(stream);
      }
    }
  }

  function endAll(reason: string): void {
    closing = true;
    stopPolling();
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
      const access = await streamAccess(ctx, session.accountId, topicId);
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
        accountId: session.accountId,
        sessionId: session.sessionId,
        expiresAt: session.expiresAt,
        res,
        lastSent: 0,
        buffer: [],
        started: false,
        closed: false,
        timer: null,
        recheckTimer: null,
        expiryTimer: null,
        queued: false,
        hinted: false,
        end(reason) {
          if (made.closed) return;
          made.closed = true;
          if (made.timer !== null) clearInterval(made.timer);
          if (made.recheckTimer !== null) clearInterval(made.recheckTimer);
          if (made.expiryTimer !== null) clearTimeout(made.expiryTimer);
          const set = byTopic.get(topicId);
          if (set !== undefined) {
            set.delete(made);
            if (set.size === 0) byTopic.delete(topicId);
          }
          slot.release();
          // Before the headers went out, the route's own reply speaks.
          if (!made.started) return;
          // The client is told why, when the server is the one that ends it.
          if (
            END_EVENT_REASONS.has(reason) &&
            !res.destroyed &&
            !res.writableEnded
          ) {
            res.write(endFrame(reason));
          }
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
      // Access holds only while it is re-checked: every interval, and at once
      // if a hint named this stream while it was opening.
      made.recheckTimer = setInterval(() => {
        if (!expireIfDue(made)) queueRecheck(made);
      }, recheckMs);
      armExpiry(made);
      if (made.hinted) queueRecheck(made);
      return reply;
    } catch (error) {
      if (stream !== null) stream.end("error");
      throw error;
    } finally {
      if (stream === null) slot.release();
    }
  });

  return { notify, aclNotify, listenDown, listenUp, endAll, reserve };
}
