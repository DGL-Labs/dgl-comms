import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import type { FastifyError, FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { loadBlocklist } from "./blocklist.ts";
import type { Config } from "./config.ts";
import { systemClock } from "./context.ts";
import type { Clock, Ctx } from "./context.ts";
import { isBusyError, startListener } from "./db.ts";
import type { Listener } from "./db.ts";
import type { EmailSender } from "./email.ts";
import { createLogger } from "./log.ts";
import type { LogSink } from "./log.ts";
import { registerRoutes } from "./routes.ts";
import { registerLongPollRoutes } from "./long-poll.ts";
import { registerStreamRoutes } from "./stream.ts";

export interface AppDeps {
  pool: Pool;
  config: Config;
  sender: EmailSender;
  clock?: Clock;
  // Defaults to reading config.blocklistPath once, now.
  blocklist?: ReadonlySet<string>;
  // Streams use this from C-1e. In C-1b the default is a no-op; tests pass a
  // function to observe it.
  onSessionRevoked?: (sessionIds: string[]) => void;
  logSink?: LogSink;
  // Tests only. Never read from config or the environment.
  testHooks?: {
    skipPermissionChecks?: boolean;
    holdAfterSeqMs?: number;
    lockTimeoutMs?: number;
    streamKeepaliveMs?: number;
    streamProcessCap?: number;
    streamSessionCap?: number;
    streamRecheckMs?: number;
    streamPollMs?: number;
    listenBackoffMs?: number;
  };
}

// The LISTEN reconnect delay: 1 s, doubling, up to 30 s.
const LISTEN_BACKOFF_MS = 1000;
const LISTEN_BACKOFF_FACTOR = 30;

export function buildApp(deps: AppDeps): FastifyInstance {
  const logger = createLogger(deps.logSink);
  const onSessionRevoked = deps.onSessionRevoked ?? (() => undefined);
  const ctx: Ctx = {
    pool: deps.pool,
    config: deps.config,
    sender: deps.sender,
    clock: deps.clock ?? systemClock,
    blocklist: deps.blocklist ?? loadBlocklist(deps.config.blocklistPath),
    key: {
      secret: new TextEncoder().encode(deps.config.jwtKey),
      kid: deps.config.jwtKid,
    },
    logger,
    skipPermissionChecks: deps.testHooks?.skipPermissionChecks === true,
    holdAfterSeqMs: deps.testHooks?.holdAfterSeqMs ?? null,
    lockTimeoutMs: deps.testHooks?.lockTimeoutMs ?? null,
    streamKeepaliveMs: deps.testHooks?.streamKeepaliveMs ?? null,
    streamProcessCap: deps.testHooks?.streamProcessCap ?? null,
    streamSessionCap: deps.testHooks?.streamSessionCap ?? null,
    streamRecheckMs: deps.testHooks?.streamRecheckMs ?? null,
    streamPollMs: deps.testHooks?.streamPollMs ?? null,
    listenBackoffMs: deps.testHooks?.listenBackoffMs ?? null,
    sessionsRevoked(sessionIds) {
      if (sessionIds.length === 0) return;
      try {
        onSessionRevoked(sessionIds);
      } catch {
        logger.log({ event: "hook_error", reason: "session_revoked_hook" });
      }
    },
  };

  // Fastify's own logger is off: it would log request and header details.
  const app = Fastify({
    logger: false,
    genReqId: () => randomUUID(),
    // Above the worst JSON escaping of a 2,048-byte body and a 120-character
    // title (G5 S1). parseMessage keeps the real 2,048-byte body limit.
    bodyLimit: 16384,
  });
  app.decorateRequest("accountId", null);
  app.decorateRequest("reason", null);

  app.addHook("onResponse", (request, reply, done) => {
    logger.log({
      event: "request",
      request_id: request.id,
      route: request.routeOptions.url ?? null,
      status: reply.statusCode,
      latency_ms: Math.round(reply.elapsedTime),
      account_id: request.accountId,
      reason: request.reason,
    });
    done();
  });

  // Error bodies and logs never carry the error message. A lock wait that timed
  // out (SQLSTATE 55P03) or a pool with no free connection is a retryable 503
  // busy, on every route.
  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (isBusyError(error)) {
      request.reason = "busy";
      return reply.header("retry-after", "1").code(503).send({ error: "busy" });
    }
    const client =
      error.statusCode !== undefined &&
      error.statusCode >= 400 &&
      error.statusCode < 500;
    request.reason = client ? "bad_request" : "internal_error";
    return reply
      .code(client ? (error.statusCode as number) : 500)
      .send({ error: client ? "bad_request" : "internal" });
  });

  app.get("/healthz", (_request, reply) => {
    return reply.code(200).send({ ok: true });
  });

  registerRoutes(app, ctx);
  const streams = registerStreamRoutes(app, ctx);
  const polls = registerLongPollRoutes(
    app,
    ctx,
    streams,
    deps.config.longPollOn,
  );

  // The one LISTEN client of this process starts with the app (a failure to
  // start fails the app) and closes with it, after every stream has ended.
  // Streams end in preClose: Fastify closes the HTTP server before onClose
  // runs, and the server waits for open connections, which streams are.
  // If the connection drops, it is replaced with backoff while the streams
  // poll (B4); each reconnect is a new connection.
  let listener: Listener | null = null;
  let stopped = false;
  let retry: ReturnType<typeof setTimeout> | null = null;
  const firstDelay = ctx.listenBackoffMs ?? LISTEN_BACKOFF_MS;
  const longestDelay = firstDelay * LISTEN_BACKOFF_FACTOR;

  function connectListener(): Promise<Listener> {
    return startListener(
      deps.config.listenUrl,
      (channel, payload) => {
        if (channel === "pingzo_msg") {
          streams.notify(payload);
          polls.wake(payload);
        } else streams.aclNotify(payload);
      },
      onListenDown,
    );
  }

  function onListenDown(): void {
    if (stopped) return;
    listener = null;
    logger.log({ event: "listen_down", reason: "listen_down" });
    streams.listenDown();
    scheduleReconnect(firstDelay);
  }

  function scheduleReconnect(delay: number): void {
    retry = setTimeout(() => {
      retry = null;
      void reconnect(delay);
    }, delay);
  }

  async function reconnect(delay: number): Promise<void> {
    if (stopped) return;
    try {
      const fresh = await connectListener();
      if (stopped) {
        await fresh.close();
        return;
      }
      listener = fresh;
      logger.log({ event: "listen_up", reason: "listen_up" });
      streams.listenUp();
    } catch {
      scheduleReconnect(Math.min(delay * 2, longestDelay));
    }
  }

  app.addHook("onReady", async () => {
    listener = await connectListener();
  });
  app.addHook("preClose", async () => {
    polls.endAll();
    streams.endAll("server_closing");
  });
  app.addHook("onClose", async () => {
    stopped = true;
    if (retry !== null) clearTimeout(retry);
    retry = null;
    if (listener !== null) await listener.close();
    listener = null;
  });

  return app;
}
