import type { FastifyRequest } from "fastify";
import type { Pool } from "pg";
import type { Config } from "./config.ts";
import type { EmailSender } from "./email.ts";
import { resolveClientIp } from "./ip.ts";
import type { Logger } from "./log.ts";
import type { JwtKey } from "./sessions.ts";

declare module "fastify" {
  interface FastifyRequest {
    // Set by auth; read by the request log. Never anything else.
    accountId: string | null;
    reason: string | null;
  }
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export interface Ctx {
  pool: Pool;
  config: Config;
  sender: EmailSender;
  clock: Clock;
  blocklist: ReadonlySet<string>;
  key: JwtKey;
  logger: Logger;
  // Test hook: skips the permission check, to prove that row-level security
  // holds by itself. Always false outside tests.
  skipPermissionChecks: boolean;
  // Test hooks for publish, from AppDeps.testHooks only, never from config:
  // hold the transaction after it takes its seq, and override lock_timeout.
  // Null outside tests. To be excluded from production builds later.
  holdAfterSeqMs: number | null;
  lockTimeoutMs: number | null;
  // Test hooks for streams, from AppDeps.testHooks only, never from config:
  // the keepalive interval, the per-process stream cap, the access re-check
  // interval, the outage poll interval, and the first LISTEN reconnect delay.
  // Null outside tests.
  streamKeepaliveMs: number | null;
  streamProcessCap: number | null;
  // The per-session stream cap, for the load job only (3 otherwise).
  streamSessionCap: number | null;
  streamRecheckMs: number | null;
  streamPollMs: number | null;
  listenBackoffMs: number | null;
  // Wraps the onSessionRevoked hook; ignores empty lists and hook errors.
  sessionsRevoked(sessionIds: string[]): void;
}

export function clientIp(ctx: Ctx, request: FastifyRequest): string {
  return resolveClientIp(
    request.socket.remoteAddress,
    request.headers["cf-connecting-ip"],
    ctx.config.trustedProxies,
  );
}
