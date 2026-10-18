import { appendFileSync } from "node:fs";
import http from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { FastifyInstance } from "fastify";
import pg from "pg";
import type { Pool, PoolClient } from "pg";
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
  // Tables are emptied with DELETE: pingzo_app has no TRUNCATE. Workspaces go
  // first: they reference accounts, and members, invitations, limits and keys
  // cascade from them. audit_log is append-only, so it is never emptied; tests
  // read it by workspace id.
  // The delete policy on workspaces follows the context, so the context here
  // names every workspace.
  await withAllWorkspaces(pool, (c) => c.query("DELETE FROM workspaces"));
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

// Runs fn in a transaction (committed) whose context names every workspace, for
// test setup that must change a workspace row directly.
export async function withAllWorkspaces<T>(
  pool: Pool,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // SELECT on workspaces is scoped: a row is visible by id or by its owner.
    // Every workspace has an owner, so reading as each account in turn finds
    // them all.
    const accounts = await client.query<{ id: string }>(
      "SELECT id FROM accounts",
    );
    const ids: string[] = [];
    for (const account of accounts.rows) {
      await client.query("SELECT set_config('app.account_id', $1, true)", [
        account.id,
      ]);
      const owned = await client.query<{ id: string }>(
        "SELECT id FROM workspaces",
      );
      for (const row of owned.rows) ids.push(row.id);
    }
    await client.query("SELECT set_config('app.account_id', '', true)");
    await client.query("SELECT set_config('app.workspace_ids', $1, true)", [
      `{${ids.join(",")}}`,
    ]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
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

export type Method = "GET" | "POST" | "PATCH" | "DELETE";

export interface User extends Tokens {
  email: string;
}

// An authenticated request.
export function api(
  t: TestApp,
  who: Tokens,
  method: Method,
  url: string,
  payload?: object,
) {
  return t.app.inject({
    method,
    url,
    headers: bearer(who.accessToken),
    ...(payload === undefined ? {} : { payload }),
  });
}

let userCounter = 0;

// A verified account. Each one signs up from its own address, so the per-IP
// sign-up cap never gets in the way.
export async function makeUser(t: TestApp): Promise<User> {
  userCounter += 1;
  const email = uniqueEmail();
  const tokens = await signupAndVerify(
    t,
    email,
    `198.51.100.${(userCounter % 250) + 1}`,
  );
  return { ...tokens, email };
}

export async function createWorkspace(
  t: TestApp,
  who: Tokens,
  name = "Test workspace",
  kind: "client" | "team" = "team",
): Promise<string> {
  const res = await api(t, who, "POST", "/v1/workspaces", { name, kind });
  if (res.statusCode !== 201) {
    throw new Error(`workspace create gave ${res.statusCode}`);
  }
  return res.json<{ id: string }>().id;
}

// Invites the user and has them accept, through the API.
export async function addMember(
  t: TestApp,
  inviter: Tokens,
  workspaceId: string,
  user: User,
  role: "admin" | "member" = "member",
): Promise<void> {
  const res = await api(
    t,
    inviter,
    "POST",
    `/v1/workspaces/${workspaceId}/invitations`,
    { email: user.email, role },
  );
  if (res.statusCode !== 201) throw new Error(`invite gave ${res.statusCode}`);
  const message = t.sender.lastTo(user.email);
  if (message === undefined || message.kind !== "invite") {
    throw new Error("no invite email was sent");
  }
  registerSecret(message.token);
  const joined = await api(t, user, "POST", "/v1/invitations/accept", {
    token: message.token,
  });
  if (joined.statusCode !== 200) {
    throw new Error(`accept gave ${joined.statusCode}`);
  }
}

// A second app on the same database, with a test hook set.
export async function appWithHooks(
  t: TestApp,
  testHooks: {
    skipPermissionChecks?: boolean;
    holdAfterSeqMs?: number;
    lockTimeoutMs?: number;
    streamKeepaliveMs?: number;
    streamProcessCap?: number;
  },
): Promise<FastifyInstance> {
  const logFile = inject("logFile");
  const app = buildApp({
    pool: t.pool,
    config: t.config,
    sender: t.sender,
    clock: t.clock,
    blocklist: new Set(),
    testHooks,
    logSink: (line) => appendFileSync(logFile, `${line}\n`),
  });
  await app.ready();
  return app;
}

export interface SseEvent {
  id: string | null;
  event: string;
  data: string;
}

// A stream read over a real socket (inject does not stream). Error replies
// (401, 429 and so on) come back as a status and a body, with no events.
export interface StreamClient {
  status: number;
  headers: IncomingHttpHeaders;
  events: SseEvent[];
  comments: string[];
  body: string;
  closed: boolean;
  until(check: () => boolean, ms?: number): Promise<void>;
  close(): void;
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Polls until check passes, or throws once ms have passed.
export async function until(check: () => boolean, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("timed out waiting for a condition");
    await sleepMs(20);
  }
}

// Starts the app on a free port of 127.0.0.1 and returns its base URL.
export function listenOnFreePort(app: FastifyInstance): Promise<string> {
  return app.listen({ host: "127.0.0.1", port: 0 });
}

// GET /v1/topics/:id/stream, resolved once the response headers are in.
export function openStream(
  baseUrl: string,
  topicId: string,
  headers: Record<string, string> = {},
  query = "",
): Promise<StreamClient> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      `${baseUrl}/v1/topics/${topicId}/stream${query}`,
      { headers },
      (res) => {
        res.setEncoding("utf8");
        let pending = "";
        const client: StreamClient = {
          status: res.statusCode ?? 0,
          headers: res.headers,
          events: [],
          comments: [],
          body: "",
          closed: false,
          until: (check, ms) => until(check, ms),
          close: () => req.destroy(),
        };
        res.on("data", (chunk: string) => {
          client.body += chunk;
          pending += chunk;
          let end = pending.indexOf("\n\n");
          while (end !== -1) {
            const block = pending.slice(0, end);
            pending = pending.slice(end + 2);
            end = pending.indexOf("\n\n");
            const lines = block.split("\n");
            if (lines.every((line) => line.startsWith(":"))) {
              client.comments.push(...lines);
              continue;
            }
            const event: SseEvent = { id: null, event: "message", data: "" };
            for (const line of lines) {
              if (line.startsWith("id: ")) event.id = line.slice(4);
              else if (line.startsWith("event: ")) event.event = line.slice(7);
              else if (line.startsWith("data: ")) event.data = line.slice(6);
            }
            client.events.push(event);
          }
        });
        res.on("close", () => {
          client.closed = true;
        });
        resolve(client);
      },
    );
    req.on("error", reject);
  });
}

// Runs raw SQL as pingzo_app in a transaction with the given request context
// (set the way withContext does), then rolls back. For testing row-level
// security directly, without the helpers in src/db.ts.
export async function inContext<T>(
  pool: Pool,
  settings: { accountId?: string; workspaceIds?: string[]; raw?: string },
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (settings.accountId !== undefined) {
      await client.query("SELECT set_config('app.account_id', $1, true)", [
        settings.accountId,
      ]);
    }
    if (settings.workspaceIds !== undefined) {
      await client.query("SELECT set_config('app.workspace_ids', $1, true)", [
        `{${settings.workspaceIds.join(",")}}`,
      ]);
    }
    if (settings.raw !== undefined) {
      await client.query("SELECT set_config('app.workspace_ids', $1, true)", [
        settings.raw,
      ]);
    }
    return await fn(client);
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

// A pool as pingzo_owner, to change a limit that the app cannot change.
export function ownerPool(): Pool {
  return new pg.Pool({ connectionString: inject("ownerUrl"), max: 2 });
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
