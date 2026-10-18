import { appendFileSync } from "node:fs";
import pg from "pg";
import type { PoolClient } from "pg";
import { afterEach, beforeEach, describe, expect, inject, it } from "vitest";
import { buildApp } from "../../src/app.ts";
import { createPool } from "../../src/db.ts";
import {
  api,
  bearer,
  createWorkspace,
  makeApp,
  makeUser,
  ownerPool,
} from "./harness.ts";
import type { TestApp, User } from "./harness.ts";

// T-POOL and the central busy handler (A7): the pool budget, and 503 `busy`
// for a pool with no free connection and for a lock wait over lock_timeout.
describe("pool budget and busy", () => {
  let t: TestApp;
  let user: User;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    user = await makeUser(t);
  });
  afterEach(() => t.close());

  function appOn(pool: pg.Pool) {
    const logFile = inject("logFile");
    return buildApp({
      pool,
      config: t.config,
      sender: t.sender,
      clock: t.clock,
      blocklist: new Set(),
      logSink: (line) => appendFileSync(logFile, `${line}\n`),
    });
  }

  it("createPool gives 8 connections, a 2 second wait and the timeouts", async () => {
    const pool = createPool(inject("dbUrl"));
    try {
      expect(pool.options.max).toBe(8);
      expect(pool.options.connectionTimeoutMillis).toBe(2000);
      const res = await pool.query<{ s: string; l: string; i: string }>(
        `SELECT current_setting('statement_timeout') AS s,
                current_setting('lock_timeout') AS l,
                current_setting('idle_in_transaction_session_timeout') AS i`,
      );
      expect(res.rows[0]).toEqual({ s: "5s", l: "3s", i: "10s" });
    } finally {
      await pool.end();
    }
  });

  it("with the pool exhausted, a request gets 503 busy within 2 seconds", async () => {
    const pool = createPool(inject("dbUrl"));
    const app = appOn(pool);
    const held: PoolClient[] = [];
    try {
      for (let i = 0; i < 8; i += 1) held.push(await pool.connect());
      const started = Date.now();
      const res = await app.inject({
        method: "GET",
        url: "/v1/workspaces",
        headers: bearer(user.accessToken),
      });
      const waited = Date.now() - started;

      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ error: "busy" });
      expect(res.headers["retry-after"]).toBe("1");
      // The pool gives up after 2 seconds; a little slack for the test runner.
      expect(waited).toBeLessThan(2500);

      // Once connections come back, the same request works.
      for (const client of held.splice(0)) client.release();
      const again = await app.inject({
        method: "GET",
        url: "/v1/workspaces",
        headers: bearer(user.accessToken),
      });
      expect(again.statusCode).toBe(200);
    } finally {
      for (const client of held) client.release();
      await app.close();
      await pool.end();
    }
  }, 20_000);

  it("a lock wait over lock_timeout gives 503 busy on a non-publish route", async () => {
    const ws = await createWorkspace(t, user, "Locked");
    // A pool like the api's, with a short lock timeout so the test is quick.
    const strict = new pg.Pool({
      connectionString: inject("dbUrl"),
      max: 3,
      options: "-c lock_timeout=500",
    });
    const app = appOn(strict);
    const db = ownerPool();
    const holder = await db.connect();
    try {
      // Another transaction holds the workspace row, as a slow request would.
      await holder.query("BEGIN");
      await holder.query("SELECT set_config('app.workspace_ids', $1, true)", [
        `{${ws}}`,
      ]);
      await holder.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [
        ws,
      ]);

      const blocked = await app.inject({
        method: "POST",
        url: `/v1/workspaces/${ws}/topics`,
        headers: bearer(user.accessToken),
        payload: { name: "Waits" },
      });
      expect(blocked.statusCode).toBe(503);
      expect(blocked.json()).toEqual({ error: "busy" });
      expect(blocked.headers["retry-after"]).toBe("1");

      // A retry after the lock is gone goes through, and the blocked attempt
      // left nothing behind.
      await holder.query("ROLLBACK");
      const retry = await app.inject({
        method: "POST",
        url: `/v1/workspaces/${ws}/topics`,
        headers: bearer(user.accessToken),
        payload: { name: "Waits" },
      });
      expect(retry.statusCode).toBe(201);
      const list = await api(t, user, "GET", `/v1/workspaces/${ws}/topics`);
      expect(list.json<{ topics: unknown[] }>().topics).toHaveLength(1);
    } finally {
      await holder.query("ROLLBACK").catch(() => undefined);
      holder.release();
      await db.end();
      await app.close();
      await strict.end();
    }
  });
});
