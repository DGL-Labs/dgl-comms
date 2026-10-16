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
