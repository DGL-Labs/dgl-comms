import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  api,
  appWithHooks,
  bearer,
  createWorkspace,
  killListeners,
  listenOnFreePort,
  makeApp,
  makeUser,
  openStream,
  ownerPool,
} from "./harness.ts";
import type { StreamClient, TestApp, User } from "./harness.ts";

const CLIENTS = 50;
const PER_SECOND = 10;
const SECONDS = 60;
const STALL_AT_S = 20;
const KILL_AT_S = 40;
const ADDRESSES = 15;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function seqs(client: StreamClient): number[] {
  return client.events
    .filter((e) => e.event === "message")
    .map((e) => (JSON.parse(e.data) as { seq: number }).seq);
}

// The load job (plan section 6, PC ruling D2: inside the integration job). 50
// stream clients and 10 publishes a second for 60 s, with one commit held for
// 15 s and one LISTEN kill. Every client gets every seq exactly once, in
// order, with no gap.
describe("stream load", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let topic: string;
  let key: string;
  let hooked: FastifyInstance | null;
  let stalled: FastifyInstance | null;
  let clients: StreamClient[];

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    db = ownerPool();
    owner = await makeUser(t);
    const ws = await createWorkspace(t, owner, "Load");
    // The load is above the workspace's default rates on purpose.
    await db.query(
      `UPDATE workspace_limits SET msgs_per_min = 100000, msgs_per_day = 100000
        WHERE workspace_id = $1`,
      [ws],
    );
    const made = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
      name: "Load",
    });
    expect(made.statusCode).toBe(201);
    topic = made.json<{ id: string }>().id;
    const keyed = await api(t, owner, "POST", `/v1/topics/${topic}/keys`);
    expect(keyed.statusCode).toBe(201);
    key = keyed.json<{ key: string }>().key;
    hooked = null;
    stalled = null;
    clients = [];
  });
  afterEach(async () => {
    for (const client of clients) client.close();
    if (hooked !== null) await hooked.close();
    if (stalled !== null) await stalled.close();
    await db.end();
    await t.close();
  });

  // One publish through the topic key, from one of several client addresses
  // (the caller bucket is per address). A 503 busy (the held commit) is retried
  // with the same Idempotency-Key, so each publish makes exactly one message.
  async function publish(app: FastifyInstance, n: number): Promise<void> {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const res = await app.inject({
        method: "POST",
        url: `/v1/topics/${topic}/messages`,
        remoteAddress: `203.0.113.${(n % ADDRESSES) + 1}`,
        headers: {
          ...bearer(key),
          "idempotency-key": `load-${n}`,
        },
        payload: { body: `load ${n}` },
      });
      if (res.statusCode === 201) return;
      expect(res.statusCode, `publish ${n}`).toBe(503);
      await sleep(500);
    }
    throw new Error(`publish ${n} did not go through`);
  }

  it("50 clients, 10 publishes a second for 60 s, a 15 s stall and a LISTEN kill: every seq exactly once", async () => {
    hooked = await appWithHooks(t, {
      streamSessionCap: CLIENTS,
      listenBackoffMs: 200,
      streamPollMs: 300,
    });
    stalled = await appWithHooks(t, { holdAfterSeqMs: 15_000 });
    const url = await listenOnFreePort(hooked);
    for (let i = 0; i < CLIENTS; i += 1) {
      const client = await openStream(url, topic, bearer(owner.accessToken));
      expect(client.status).toBe(200);
      clients.push(client);
    }

    const started = Date.now();
    const sent: Promise<void>[] = [];
    const total = PER_SECOND * SECONDS;
    for (let n = 0; n < total; n += 1) {
      const due = started + (n * 1000) / PER_SECOND;
      const wait = due - Date.now();
      if (wait > 0) await sleep(wait);
      if (n === STALL_AT_S * PER_SECOND) sent.push(publish(stalled, total));
      if (n === KILL_AT_S * PER_SECOND) {
        expect((await killListeners(t.pool)).length).toBeGreaterThan(0);
      }
      sent.push(publish(t.app, n));
    }
    await Promise.all(sent);

    const expected = Array.from({ length: total + 1 }, (_, i) => i + 1);
    const deadline = Date.now() + 60_000;
    while (clients.some((c) => seqs(c).length < expected.length)) {
      if (Date.now() > deadline) break;
      await sleep(200);
    }
    for (const [i, client] of clients.entries()) {
      expect(client.closed, `client ${i} closed`).toBe(false);
      expect(seqs(client), `client ${i}`).toEqual(expected);
      expect(
        client.events.filter((e) => e.event === "gap"),
        `client ${i} gaps`,
      ).toEqual([]);
    }
  }, 240_000);
});
