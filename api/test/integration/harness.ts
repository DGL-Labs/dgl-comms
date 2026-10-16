import { appendFileSync } from "node:fs";
import type { FastifyInstance } from "fastify";
import pg from "pg";
import type { Pool } from "pg";
import { inject } from "vitest";
import { buildApp } from "../../src/app.ts";
import { loadConfig } from "../../src/config.ts";
import type { Config } from "../../src/config.ts";
import { parseTrustedProxies } from "../../src/ip.ts";
import { TestSink } from "../../src/email.ts";
import type { Clock } from "../../src/context.ts";

export class FakeClock implements Clock {
  private ms = Date.now();

  now(): Date {
    return new Date(this.ms);
  }

  advance(ms: number): void {
    this.ms += ms;
  }
}

export interface TestApp {
  app: FastifyInstance;
  pool: Pool;
  sender: TestSink;
  clock: FakeClock;
  revoked: string[][];
  config: Config;
  close(): Promise<void>;
}

export interface Tokens {
  accountId: string;
  accessToken: string;
  refreshToken: string;
}

// Values that must never show up in the logs. The T-LOGS test reads them.
export function registerSecret(value: string): void {
  appendFileSync(inject("secretsFile"), `${value}\n`);
}

export function testConfig(overrides: Partial<Config> = {}): Config {
  const env = process.env;
  const config = loadConfig({
    PINGZO_DATABASE_URL: inject("dbUrl"),
    PINGZO_JWT_KEY:
      env.PINGZO_JWT_KEY ?? "test-only-jwt-key-test-only-jwt-key-0000",
    PINGZO_TEAM_ALLOWLIST:
      env.PINGZO_TEAM_ALLOWLIST ?? "a@example.test,b@example.test",
    PINGZO_ALLOWLIST_ON: env.PINGZO_ALLOWLIST_ON ?? "true",
    PINGZO_TRUSTED_PROXIES: env.PINGZO_TRUSTED_PROXIES ?? "",
  });
  return { ...config, ...overrides };
}

export function trustedProxies(csv: string): Config["trustedProxies"] {
  return parseTrustedProxies(csv);
}

export async function makeApp(
  overrides: Partial<Config> = {},
  blocklist?: ReadonlySet<string>,
): Promise<TestApp> {
  const config = testConfig(overrides);
  const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 5 });
  // Tables are emptied with DELETE: pingzo_app has no TRUNCATE.
  await pool.query("DELETE FROM accounts");
  await pool.query("DELETE FROM login_failures");
  await pool.query("DELETE FROM signup_events");

  const sender = new TestSink();
  const clock = new FakeClock();
  const revoked: string[][] = [];
  const logFile = inject("logFile");
  const app = buildApp({
    pool,
    config,
    sender,
    clock,
    blocklist,
    onSessionRevoked: (ids) => revoked.push(ids),
    logSink: (line) => appendFileSync(logFile, `${line}\n`),
  });
  await app.ready();
  return {
    app,
    pool,
    sender,
    clock,
    revoked,
    config,
    async close() {
      await app.close();
      await pool.end();
    },
  };
}

let counter = 0;

// A fresh @example.test address, so tests never reuse one by accident.
export function uniqueEmail(): string {
  counter += 1;
  return `user${counter}-${Date.now()}@example.test`;
}

export function bearer(accessToken: string): Record<string, string> {
  registerSecret(accessToken);
  return { authorization: `Bearer ${accessToken}` };
}

export async function signup(
  t: TestApp,
  email: string,
  remoteAddress = "198.51.100.1",
) {
  registerSecret(email);
  return t.app.inject({
    method: "POST",
    url: "/v1/auth/signup",
    remoteAddress,
    payload: { email, age_attested: true },
  });
}

export async function redeem(
  t: TestApp,
  token: string,
  remoteAddress = "198.51.100.1",
  headers: Record<string, string> = {},
) {
  registerSecret(token);
  return t.app.inject({
    method: "POST",
    url: "/v1/auth/redeem",
    remoteAddress,
    headers,
    payload: { token },
  });
}

// Signs up, redeems the verify link, and returns the session tokens.
export async function signupAndVerify(
  t: TestApp,
  email: string,
  remoteAddress = "198.51.100.1",
): Promise<Tokens> {
  const res = await signup(t, email, remoteAddress);
  if (res.statusCode !== 202) throw new Error(`signup gave ${res.statusCode}`);
  const message = t.sender.lastTo(email);
  if (message === undefined) throw new Error("no verify email was sent");
  const redeemed = await redeem(t, message.token, remoteAddress);
  if (redeemed.statusCode !== 200) {
    throw new Error(`redeem gave ${redeemed.statusCode}`);
  }
  const body = redeemed.json<{ access_token: string; refresh_token: string }>();
  registerSecret(body.access_token);
  registerSecret(body.refresh_token);
  const account = await t.pool.query<{ id: string }>(
    "SELECT id FROM accounts WHERE email = $1",
    [email],
  );
  return {
    accountId: (account.rows[0] as { id: string }).id,
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
  };
}
