import { appendFileSync } from "node:fs";
import http from "node:http";
import type { FastifyInstance } from "fastify";
import pg from "pg";
import type { Pool, PoolClient } from "pg";
import { afterEach, beforeEach, describe, expect, inject, it } from "vitest";
import { buildApp } from "../../src/app.ts";
import {
  addMember,
  api,
  appWithHooks,
  bearer,
  createWorkspace,
  listenOnFreePort,
  makeApp,
  makeUser,
  openStream,
  ownerPool,
  registerSecret,
} from "./harness.ts";
import type { StreamClient, TestApp, Tokens, User } from "./harness.ts";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Resolves to the value, or to null if it takes longer than ms.
function within<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([promise, sleep(ms).then(() => null)]);
}

// The last event of a stream that the server ended: event: end, no id: line.
function endOf(client: StreamClient): { reason: string } | null {
  const last = client.events[client.events.length - 1];
  if (last === undefined || last.event !== "end" || last.id !== null) {
    return null;
  }
  return JSON.parse(last.data) as { reason: string };
}

// G5 on dbe3e586 (C1E-FIX-2): a stream that is still opening at shutdown
// (MUST-1), a client that leaves while its session is read (SHOULD-3), a token
// refresh (SHOULD-1) and a re-check that keeps failing (SHOULD-6).
describe("stream: shutdown while opening, early disconnect, refresh, failing re-check", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let member: User;
  let ws: string;
  let topic: string;
  let apps: FastifyInstance[];
  let clients: StreamClient[];
  let held: PoolClient | null;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    db = ownerPool();
    owner = await makeUser(t);
    member = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    const res = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
      name: "Alerts",
    });
    expect(res.statusCode).toBe(201);
    topic = res.json<{ id: string }>().id;
    apps = [];
    clients = [];
    held = null;
  });
  afterEach(async () => {
    await letGo();
    for (const client of clients) client.close();
    for (const app of apps) await app.close();
    await db.end();
    await t.close();
  });

  async function startApp(
    hooks: Parameters<typeof appWithHooks>[1],
  ): Promise<{ app: FastifyInstance; url: string }> {
    const app = await appWithHooks(t, hooks);
    apps.push(app);
    return { app, url: await listenOnFreePort(app) };
  }

  async function open(url: string, who: Tokens): Promise<StreamClient> {
    const client = await openStream(url, topic, bearer(who.accessToken));
    clients.push(client);
    return client;
  }

  // Locks a table in an open transaction, as the owner role, so that the
  // app's next read of it waits until letGo().
  async function hold(table: "topics" | "sessions"): Promise<void> {
    held = await db.connect();
    await held.query("BEGIN");
    await held.query(`LOCK TABLE ${table} IN ACCESS EXCLUSIVE MODE`);
  }

  async function letGo(): Promise<void> {
    if (held === null) return;
    const client = held;
    held = null;
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }

  // Waits until one of the app's backends waits on a lock (pingzo_app sees
  // its own backends in pg_stat_activity).
  async function lockWaiter(): Promise<void> {
    const end = Date.now() + 5000;
    for (;;) {
      const res = await t.pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_stat_activity
          WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid()`,
      );
      if ((res.rows[0]?.n ?? 0) > 0) return;
      if (Date.now() > end) throw new Error("no backend waits on the lock");
      await sleep(50);
    }
  }

  it("answers a stream that is opening at shutdown with 503, and app.close() finishes", async () => {
    const { app, url } = await startApp({});
    // The access check reads topics, so the open waits there.
    await hold("topics");
    const opening = openStream(url, topic, bearer(owner.accessToken));
    await lockWaiter();
    apps.splice(apps.indexOf(app), 1);
    const closed = app.close().then(() => "closed");
    // preClose has run, so the server is closing, before the open goes on.
    await sleep(300);
    await letGo();

    const client = await within(opening, 5000);
    expect(client).not.toBeNull();
    if (client === null) return;
    clients.push(client);
    expect(client.status).toBe(503);
    expect(client.headers["retry-after"]).toBe("1");
    await client.until(() => client.closed, 5000);
    expect(JSON.parse(client.body)).toEqual({ error: "server_closing" });
    expect(await within(closed, 5000)).toBe("closed");
  });

  it("frees the slot at once when the client leaves while its session is read", async () => {
    const { url } = await startApp({ streamProcessCap: 1 });
    // requireSession reads sessions, so the open waits there.
    await hold("sessions");
    const request = http.get(`${url}/v1/topics/${topic}/stream`, {
      headers: bearer(owner.accessToken),
    });
    request.on("error", () => undefined);
    await lockWaiter();
    request.destroy();
    await sleep(300);
    await letGo();

    // With a cap of 1, another stream opens: the left request holds no slot
    // (before the fix it held one until its 15-minute token ran out).
    let status = 0;
    const end = Date.now() + 3000;
    while (status !== 200 && Date.now() < end) {
      await sleep(100);
      status = (await open(url, member)).status;
    }
    expect(status).toBe(200);
  });

  describe("token refresh", () => {
    it("ends the old token's stream with token_refreshed, and the new token streams", async () => {
      // The default re-check interval, so only the hint can be in time.
      const { url } = await startApp({ listenBackoffMs: 200 });
      const mine = await open(url, member);
      const control = await open(url, owner);
      expect(mine.status).toBe(200);
      await sleep(300);

      registerSecret(member.refreshToken);
      const res = await t.app.inject({
        method: "POST",
        url: "/v1/auth/refresh",
        payload: { refresh_token: member.refreshToken },
      });
      expect(res.statusCode).toBe(200);
      const fresh = res.json<{ access_token: string; refresh_token: string }>();
      registerSecret(fresh.access_token);
      registerSecret(fresh.refresh_token);

      await mine.until(() => mine.closed, 5000);
      expect(endOf(mine)).toEqual({ reason: "token_refreshed" });
      const again = await open(url, {
        ...member,
        accessToken: fresh.access_token,
      });
      expect(again.status).toBe(200);
      expect(control.closed).toBe(false);
    });

    it("still ends with revoked on logout-all, even after a refresh", async () => {
      const { url } = await startApp({ listenBackoffMs: 200 });
      registerSecret(member.refreshToken);
      const res = await t.app.inject({
        method: "POST",
        url: "/v1/auth/refresh",
        payload: { refresh_token: member.refreshToken },
      });
      expect(res.statusCode).toBe(200);
      const fresh = res.json<{ access_token: string; refresh_token: string }>();
      registerSecret(fresh.access_token);
      registerSecret(fresh.refresh_token);
      const now = { ...member, accessToken: fresh.access_token };
      const mine = await open(url, now);
      expect(mine.status).toBe(200);
      await sleep(300);

      const out = await t.app.inject({
        method: "POST",
        url: "/v1/auth/logout-all",
        headers: bearer(fresh.access_token),
      });
      expect(out.statusCode).toBe(204);
      await mine.until(() => mine.closed, 5000);
      expect(endOf(mine)).toEqual({ reason: "revoked" });
    });
  });

  it("ends a stream whose re-check fails 3 times in a row with server_closing", async () => {
    // A pool with a short lock timeout, so each blocked re-check fails fast.
    const strict = new pg.Pool({
      connectionString: inject("dbUrl"),
      max: 3,
      options: "-c lock_timeout=300",
    });
    const logFile = inject("logFile");
    const app = buildApp({
      pool: strict,
      config: t.config,
      sender: t.sender,
      clock: t.clock,
      blocklist: new Set(),
      testHooks: { streamRecheckMs: 200 },
      logSink: (line) => appendFileSync(logFile, `${line}\n`),
    });
    try {
      await app.ready();
      const url = await listenOnFreePort(app);
      const client = await open(url, owner);
      expect(client.status).toBe(200);
      await sleep(500);
      expect(client.closed).toBe(false);

      // Every re-check now waits on the session read and fails at 300 ms.
      await hold("sessions");
      // One failure is not enough to close it.
      await sleep(550);
      expect(client.closed).toBe(false);
      await client.until(() => client.closed, 5000);
      expect(endOf(client)).toEqual({ reason: "server_closing" });
    } finally {
      await letGo();
      await app.close();
      await strict.end();
    }
  });
});
