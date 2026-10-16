import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import type { FastifyError, FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { loadBlocklist } from "./blocklist.ts";
import type { Config } from "./config.ts";
import { systemClock } from "./context.ts";
import type { Clock, Ctx } from "./context.ts";
import type { EmailSender } from "./email.ts";
import { createLogger } from "./log.ts";
import type { LogSink } from "./log.ts";
import { registerRoutes } from "./routes.ts";

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
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const logger = createLogger(deps.logSink);
  const onSessionRevoked = deps.onSessionRevoked ?? (() => undefined);
  const ctx: Ctx = {
    pool: deps.pool,
    config: deps.config,
    sender: deps.sender,
    clock: deps.clock ?? systemClock,
    blocklist: deps.blocklist ?? loadBlocklist(deps.config.blocklistPath),
    key: new TextEncoder().encode(deps.config.jwtKey),
    logger,
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
    bodyLimit: 4096,
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

  // Error bodies and logs never carry the error message.
  app.setErrorHandler((error: FastifyError, request, reply) => {
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

  return app;
}
