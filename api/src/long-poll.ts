import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { requireSession } from "./guard.ts";
import { isRecord, isUuid } from "./input.ts";
import { keyInQuery } from "./publish.ts";
import { messageData, readReplay, streamAccess } from "./stream.ts";
import type { StreamHub } from "./stream.ts";
import { deny, notFound } from "./workspaces.ts";

const ROUTE = "/v1/topics/:id/messages";
// The longest a request waits for a new message, and the default.
const WAIT_MAX_S = 25;
// While a request waits, it reads again at least this often, so it still
// answers while LISTEN is down (the same interval as the stream poll).
const POLL_MS = 5_000;
const SEQ = /^[0-9]{1,15}$/;
const WAIT = /^[0-9]{1,2}$/;

export interface LongPollHub {
  // The raw payload of a pingzo_msg notification: a hint that wakes the
  // requests waiting on that topic, which then read again themselves.
  wake(payload: string): void;
  // Answers every waiting request at once and refuses new ones.
  endAll(): void;
}

function idParam(request: FastifyRequest): string | null {
  const params = request.params;
  const value = isRecord(params) ? params.id : undefined;
  return isUuid(value) ? value : null;
}

// GET /v1/topics/:id/messages?since=<seq>[&wait=<seconds>] (B6), the long-poll
// fallback for a client whose network buffers server-sent events. Off unless
// PINGZO_LONG_POLL is "true" (404 otherwise). It has the stream's access check
// (signed-in people only, a suspended workspace refused), RLS path, gap rule
// and limits (the same slots as streams). It holds no transaction and no
// pooled connection while it waits.
export function registerLongPollRoutes(
  app: FastifyInstance,
  ctx: Ctx,
  streams: StreamHub,
  enabled: boolean,
): LongPollHub {
  const waiting = new Map<string, Set<() => void>>();
  const pollMs = ctx.streamPollMs ?? POLL_MS;
  let closing = false;

  function wakeTopic(topicId: string): void {
    for (const wake of [...(waiting.get(topicId) ?? [])]) wake();
  }

  function wake(payload: string): void {
    const topicId = payload.split(":")[0];
    if (isUuid(topicId)) wakeTopic(topicId);
  }

  function endAll(): void {
    closing = true;
    for (const topicId of [...waiting.keys()]) wakeTopic(topicId);
  }

  // Resolves when the topic is woken, the time is up, or the client is gone.
  function pause(topicId: string, ms: number, gone: () => boolean) {
    return new Promise<void>((resolve) => {
      const set = waiting.get(topicId) ?? new Set<() => void>();
      const done = () => {
        clearTimeout(timer);
        set.delete(done);
        if (set.size === 0) waiting.delete(topicId);
        resolve();
      };
      const timer = setTimeout(done, ms);
      set.add(done);
      waiting.set(topicId, set);
      if (gone() || closing) done();
    });
  }

  app.get(ROUTE, async (request, reply) => {
    if (!enabled) return notFound(request, reply);
    if (keyInQuery(request.query)) {
      request.reason = "key_in_query";
      return reply.code(400).send({ error: "bad_request" });
    }
    // Topic keys do not read: refused before any lookup, as on the stream.
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
    const query = isRecord(request.query) ? request.query : {};
    const since = query.since;
    const wait = query.wait ?? String(WAIT_MAX_S);
    if (
      typeof since !== "string" ||
      !SEQ.test(since) ||
      typeof wait !== "string" ||
      !WAIT.test(wait) ||
      Number(wait) > WAIT_MAX_S
    ) {
      request.reason = "bad_request";
      return reply.code(400).send({ error: "bad_request" });
    }

    const slot = streams.reserve(session.sessionId);
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
    let gone = false;
    request.raw.once("close", () => {
      gone = true;
      wakeTopic(topicId);
    });
    // The socket may have closed while the session was read, before the
    // listener was attached.
    if (request.raw.socket.destroyed) gone = true;
    try {
      const access = await streamAccess(ctx, session.accountId, topicId);
      if (access.kind !== "ok") return deny(request, reply, access);
      const deadline = Date.now() + Number(wait) * 1000;
      for (;;) {
        const replay = await readReplay(
          ctx,
          session.accountId,
          access.workspaceId,
          topicId,
          Number(since),
        );
        if (replay === null) return notFound(request, reply);
        const left = deadline - Date.now();
        if (
          replay.rows.length > 0 ||
          replay.gaps.length > 0 ||
          left <= 0 ||
          gone ||
          closing
        ) {
          const lastRow = replay.rows.at(-1);
          const lastGap = replay.gaps.at(-1);
          const next = Math.max(
            Number(since),
            lastRow === undefined ? 0 : Number(lastRow.seq),
            lastGap === undefined ? 0 : lastGap.to,
          );
          return reply.header("cache-control", "no-store").send({
            messages: replay.rows.map(messageData),
            gaps: replay.gaps,
            next,
          });
        }
        await pause(topicId, Math.min(left, pollMs), () => gone);
      }
    } finally {
      slot.release();
    }
  });

  return { wake, endAll };
}
