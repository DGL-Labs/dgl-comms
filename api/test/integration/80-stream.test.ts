import { appendFileSync } from "node:fs";
import type { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, inject, it } from "vitest";
import { buildApp } from "../../src/app.ts";
import { createPool } from "../../src/db.ts";
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
  until,
  withAllWorkspaces,
} from "./harness.ts";
import type { StreamClient, TestApp, Tokens, User } from "./harness.ts";

// T-STALL holds one publish for 15 seconds, so a test there needs far more
// than the default.
const STALL_TIMEOUT = 60_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function seqs(client: StreamClient): number[] {
  return client.events
    .filter((e) => e.event === "message")
    .map((e) => (JSON.parse(e.data) as { seq: number }).seq);
}

function bodies(client: StreamClient): string[] {
  return client.events
    .filter((e) => e.event === "message")
    .map((e) => (JSON.parse(e.data) as { body: string }).body);
}

function gaps(client: StreamClient): { from: number; to: number }[] {
  return client.events
    .filter((e) => e.event === "gap")
    .map((e) => JSON.parse(e.data) as { from: number; to: number });
}

// The stream endpoint (B1 to B3): access, the opening order, the LISTEN hint,
// the gap event, the limits, and that a topic key never streams.
describe("stream", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let member: User;
  let other: User;
  let ws: string;
  let wsOther: string;
  let topic: string;
  let topicOther: string;
  let base: string;
  let clients: StreamClient[];

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    db = ownerPool();
    owner = await makeUser(t);
    member = await makeUser(t);
    other = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    wsOther = await createWorkspace(t, other, "Other team");
    topic = await makeTopic(ws, owner, "Alerts");
    topicOther = await makeTopic(wsOther, other, "Elsewhere");
    base = await listenOnFreePort(t.app);
    clients = [];
  });
  afterEach(async () => {
    for (const client of clients) client.close();
    await db.end();
    await t.close();
  });

  async function makeTopic(
    workspaceId: string,
    who: User,
    name: string,
  ): Promise<string> {
    const res = await api(
      t,
      who,
      "POST",
      `/v1/workspaces/${workspaceId}/topics`,
      { name },
    );
    expect(res.statusCode).toBe(201);
    return res.json<{ id: string }>().id;
  }

  function post(
    app: TestApp["app"],
    who: Tokens,
    topicId: string,
    body: string,
  ) {
    return app.inject({
      method: "POST",
      url: `/v1/topics/${topicId}/messages`,
      headers: bearer(who.accessToken),
      payload: { body },
    });
  }

  async function publish(
    who: Tokens,
    topicId: string,
    body = "hello",
  ): Promise<number> {
    const res = await post(t.app, who, topicId, body);
    expect(res.statusCode).toBe(201);
    return res.json<{ seq: number }>().seq;
  }

  async function open(
    who: Tokens,
    topicId: string,
    headers: Record<string, string> = {},
    query = "",
    url = base,
  ): Promise<StreamClient> {
    const client = await openStream(
      url,
      topicId,
      { ...bearer(who.accessToken), ...headers },
      query,
    );
    clients.push(client);
    return client;
  }

  async function makeKey(topicId: string, who: User): Promise<string> {
    const res = await api(t, who, "POST", `/v1/topics/${topicId}/keys`);
    expect(res.statusCode).toBe(201);
    const { id, key } = res.json<{ id: string; key: string }>();
    registerSecret(key);
    registerSecret(key.slice(key.indexOf(".") + 1));
    registerSecret(id);
    return key;
  }

  // Messages written straight into the table as the owner role, so that a
  // test does not have to publish hundreds through the rate limits.
  async function seedMessages(
    workspaceId: string,
    topicId: string,
    count: number,
  ): Promise<void> {
    await withAllWorkspaces(db, async (c) => {
      await c.query(
        `INSERT INTO messages
           (topic_id, workspace_id, seq, sender_label, sender_kind, body)
         SELECT $1::uuid, $2::uuid, g, 'Member', 'person', 'm' || g
           FROM generate_series(1, $3::int) AS g`,
        [topicId, workspaceId, count],
      );
      await c.query("UPDATE topics SET last_seq = $2 WHERE id = $1", [
        topicId,
        count,
      ]);
    });
  }

  async function setOldestKept(topicId: string, seq: number): Promise<void> {
    await withAllWorkspaces(db, (c) =>
      c.query("UPDATE topics SET oldest_kept_seq = $2 WHERE id = $1", [
        topicId,
        seq,
      ]),
    );
  }

  describe("opening", () => {
    it("sends the headers and a live message in the event format", async () => {
      const client = await open(owner, topic);
      expect(client.status).toBe(200);
      expect(client.headers["content-type"]).toBe("text/event-stream");
      expect(client.headers["cache-control"]).toBe("no-cache");
      expect(client.headers["x-accel-buffering"]).toBe("no");

      const seq = await publish(member, topic, "hello there");
      await client.until(() => client.events.length === 1);
      const [event] = client.events;
      expect(event?.id).toBe(String(seq));
      expect(event?.event).toBe("message");
      const data = JSON.parse(event?.data ?? "{}") as Record<string, unknown>;
      expect(Object.keys(data).sort()).toEqual([
        "body",
        "created_at",
        "id",
        "sender_kind",
        "sender_label",
        "seq",
        "title",
        "topic_id",
      ]);
      expect(data.seq).toBe(seq);
      expect(data.topic_id).toBe(topic);
      expect(data.body).toBe("hello there");
      expect(data.sender_kind).toBe("person");
    });

    it("without Last-Event-ID replays nothing", async () => {
      await publish(owner, topic, "old 1");
      await publish(owner, topic, "old 2");
      const client = await open(owner, topic);
      await sleep(400);
      expect(client.events).toEqual([]);
      const seq = await publish(owner, topic, "new");
      await client.until(() => client.events.length === 1);
      expect(seqs(client)).toEqual([seq]);
    });

    it("resumes after Last-Event-ID, in seq order, with no gap", async () => {
      for (let i = 1; i <= 4; i += 1) await publish(owner, topic, `m${i}`);
      const client = await open(owner, topic, { "last-event-id": "2" });
      await client.until(() => seqs(client).length >= 2);
      await sleep(300);
      expect(seqs(client)).toEqual([3, 4]);
      expect(gaps(client)).toEqual([]);
    });

    it("delivers a publish during the replay exactly once, in order", async () => {
      for (let i = 1; i <= 3; i += 1) await publish(owner, topic, `seed${i}`);
      const opening = open(owner, topic, { "last-event-id": "0" });
      const publishing = (async () => {
        for (let i = 1; i <= 5; i += 1) {
          await publish(owner, topic, `live${i}`);
        }
      })();
      const [client] = await Promise.all([opening, publishing]);
      await client.until(() => seqs(client).length >= 8);
      await sleep(400);
      expect(seqs(client)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(gaps(client)).toEqual([]);
    });

    it("sends a keepalive comment on the test interval", async () => {
      const app = await appWithHooks(t, { streamKeepaliveMs: 200 });
      try {
        const url = await listenOnFreePort(app);
        const client = await open(owner, topic, {}, "", url);
        expect(client.status).toBe(200);
        await client.until(() => client.comments.length >= 2, 3000);
        expect(client.comments[0]).toBe(": keepalive");
      } finally {
        await app.close();
      }
    });
  });

  describe("T-STALL (stream part)", () => {
    it(
      "a stalled commit delays only its own topic, and A then B arrive with no gap",
      async () => {
        const slow = await appWithHooks(t, { holdAfterSeqMs: 15_000 });
        const patient = await appWithHooks(t, { lockTimeoutMs: 30_000 });
        try {
          const a = post(slow, owner, topic, "A");
          await sleep(1500);
          const streamT = await open(owner, topic);
          const streamU = await open(other, topicOther);
          // B waits for A's topic lock.
          const b = post(patient, member, topic, "B");
          await sleep(500);

          // Topic U is not delayed while A is held.
          const u = await post(t.app, other, topicOther, "U1");
          expect(u.statusCode).toBe(201);
          await streamU.until(() => seqs(streamU).length === 1, 5000);
          expect(bodies(streamU)).toEqual(["U1"]);
          expect(streamT.events).toEqual([]);

          const [aRes, bRes] = await Promise.all([a, b]);
          expect(aRes.statusCode).toBe(201);
          expect(bRes.statusCode).toBe(201);
          const aSeq = aRes.json<{ seq: number }>().seq;
          const bSeq = bRes.json<{ seq: number }>().seq;
          expect(bSeq).toBe(aSeq + 1);

          await streamT.until(() => seqs(streamT).length >= 2, 10_000);
          await sleep(300);
          expect(seqs(streamT)).toEqual([aSeq, bSeq]);
          expect(bodies(streamT)).toEqual(["A", "B"]);
          expect(gaps(streamT)).toEqual([]);
        } finally {
          await slow.close();
          await patient.close();
        }
      },
      STALL_TIMEOUT,
    );
  });

  describe("gap event", () => {
    it("tells the client what was purged, then replays from oldest_kept_seq", async () => {
      for (let i = 1; i <= 5; i += 1) await publish(owner, topic, `m${i}`);
      await setOldestKept(topic, 4);
      const client = await open(owner, topic, { "last-event-id": "1" });
      await client.until(() => seqs(client).length >= 2);
      await sleep(300);
      expect(gaps(client)).toEqual([{ from: 2, to: 3 }]);
      expect(seqs(client)).toEqual([4, 5]);
      // The gap comes first and has no id: line.
      expect(client.events[0]?.event).toBe("gap");
      expect(client.events[0]?.id).toBeNull();
    });

    it("tells the client about a 501-message gap, then replays the newest 500", async () => {
      await seedMessages(ws, topic, 501);
      const client = await open(owner, topic, { "last-event-id": "0" });
      await client.until(() => seqs(client).length >= 500, 15_000);
      await sleep(300);
      expect(gaps(client)).toEqual([{ from: 1, to: 1 }]);
      expect(client.events[0]?.event).toBe("gap");
      const got = seqs(client);
      expect(got).toHaveLength(500);
      expect(got[0]).toBe(2);
      expect(got[499]).toBe(501);
      expect(got).toEqual([...got].sort((x, y) => x - y));
    });

    it("sends both gaps when some are purged and the rest are too many", async () => {
      await seedMessages(ws, topic, 700);
      await setOldestKept(topic, 101);
      const client = await open(owner, topic, { "last-event-id": "10" });
      await client.until(() => seqs(client).length >= 500, 15_000);
      await sleep(300);
      expect(gaps(client)).toEqual([
        { from: 11, to: 100 },
        { from: 101, to: 200 },
      ]);
      expect(seqs(client)[0]).toBe(201);
      expect(seqs(client)).toHaveLength(500);
    });
  });

  describe("N7: the LISTEN payload is a hint only", () => {
    it("a forged notify delivers nothing to any stream", async () => {
      const otherSeq = await publish(other, topicOther, "secret elsewhere");
      const mine = await open(owner, topic);
      const theirs = await open(other, topicOther);
      await sleep(300);

      const forge = (payload: string) =>
        t.pool.query("SELECT pg_notify('pingzo_msg', $1)", [payload]);
      // Another workspace's topic, with a row that exists.
      await forge(`${topicOther}:${otherSeq}`);
      // A topic with streams, and a seq that does not exist.
      await forge(`${topic}:99`);
      await forge(`${topicOther}:99`);
      // Payloads that are not <topic_id>:<seq>.
      await forge("garbage");
      await forge(`${topic}:1:2`);
      await forge(`${topic}:-1`);
      await sleep(600);

      expect(mine.events).toEqual([]);
      // The row exists and is visible there, but the stream has it already.
      expect(theirs.events).toEqual([]);
    });
  });

  describe("limits", () => {
    it("refuses the 4th stream of one session with 429, and frees a slot on disconnect", async () => {
      const first = await open(owner, topic);
      await open(owner, topic);
      await open(owner, topic);
      expect(first.status).toBe(200);
      const fourth = await open(owner, topic);
      await fourth.until(() => fourth.closed);
      expect(fourth.status).toBe(429);
      expect(fourth.headers["retry-after"]).toBe("5");
      expect(JSON.parse(fourth.body)).toEqual({ error: "stream_limit" });

      // Another session of the same person is not counted with this one.
      const second = await open(member, topic);
      expect(second.status).toBe(200);

      first.close();
      let again = fourth;
      const end = Date.now() + 5000;
      while (again.status !== 200 && Date.now() < end) {
        await sleep(100);
        again = await open(owner, topic);
      }
      expect(again.status).toBe(200);
    });

    it("refuses a stream over the per-process cap with 429", async () => {
      const app = await appWithHooks(t, { streamProcessCap: 2 });
      try {
        const url = await listenOnFreePort(app);
        const one = await open(owner, topic, {}, "", url);
        const two = await open(member, topic, {}, "", url);
        const three = await open(owner, topic, {}, "", url);
        expect([one.status, two.status, three.status]).toEqual([200, 200, 429]);
      } finally {
        await app.close();
      }
    });

    it("removes a stream from the count as soon as the client disconnects", async () => {
      const app = await appWithHooks(t, { streamProcessCap: 1 });
      try {
        const url = await listenOnFreePort(app);
        const one = await open(owner, topic, {}, "", url);
        expect(one.status).toBe(200);
        expect((await open(owner, topic, {}, "", url)).status).toBe(429);
        one.close();
        let status = 429;
        const end = Date.now() + 5000;
        while (status !== 200 && Date.now() < end) {
          await sleep(100);
          status = (await open(owner, topic, {}, "", url)).status;
        }
        expect(status).toBe(200);
      } finally {
        await app.close();
      }
    });

    it("rejects a bad Last-Event-ID with 400", async () => {
      for (const value of ["abc", "-1", "1.5", "", "1e3", "9".repeat(20)]) {
        const client = await open(owner, topic, { "last-event-id": value });
        expect(client.status, `Last-Event-ID "${value}"`).toBe(400);
      }
      const zero = await open(owner, topic, { "last-event-id": "0" });
      expect(zero.status).toBe(200);
    });

    it("ends every stream when the app closes", async () => {
      const app = await appWithHooks(t, {});
      const url = await listenOnFreePort(app);
      const client = await open(owner, topic, {}, "", url);
      expect(client.status).toBe(200);
      await app.close();
      await client.until(() => client.closed, 5000);
    });
  });

  describe("access", () => {
    it("gives 401 without a valid access token", async () => {
      const none = await openStream(base, topic);
      clients.push(none);
      expect(none.status).toBe(401);
      const bad = await openStream(base, topic, {
        authorization: "Bearer not-a-token",
      });
      clients.push(bad);
      expect(bad.status).toBe(401);
    });

    it("gives a member of workspace X 404 for workspace Y's topic", async () => {
      const denied = await open(member, topicOther);
      await denied.until(() => denied.closed);
      expect(denied.status).toBe(404);
      expect(JSON.parse(denied.body)).toEqual({ error: "not_found" });
      // A topic that does not exist looks the same.
      const unknown = "7b1f0c52-5a3e-4f58-9d52-0c1f3a9d4e11";
      const missing = await open(member, unknown);
      expect(missing.status).toBe(404);
      const malformed = await open(member, "not-a-uuid");
      expect(malformed.status).toBe(404);
    });
  });

  describe("topic keys do not stream", () => {
    it("gives a valid key 401 and registers no stream; a key in the query gets 400", async () => {
      const app = await appWithHooks(t, { streamProcessCap: 1 });
      try {
        const url = await listenOnFreePort(app);
        const keyHere = await makeKey(topic, owner);
        const keyOtherTopic = await makeKey(topicOther, other);
        const byKey = (key: string, id: string) =>
          openStream(url, id, { authorization: `Bearer ${key}` });

        const valid = await byKey(keyHere, topic);
        const wrongTopic = await byKey(keyOtherTopic, topic);
        const forTopicOther = await byKey(keyOtherTopic, topicOther);
        clients.push(valid, wrongTopic, forTopicOther);
        expect(valid.status).toBe(401);
        expect(wrongTopic.status).toBe(401);
        expect(forTopicOther.status).toBe(401);

        const inQuery = await open(
          owner,
          topic,
          {},
          `?key=${encodeURIComponent(keyHere)}`,
          url,
        );
        const asToken = await open(
          owner,
          topic,
          {},
          `?access_token=${encodeURIComponent(keyHere)}`,
          url,
        );
        expect(inQuery.status).toBe(400);
        expect(asToken.status).toBe(400);

        // None of the refusals took a slot: with a cap of 1, a person's
        // stream opens, and exactly one.
        const person = await open(owner, topic, {}, "", url);
        expect(person.status).toBe(200);
        const second = await open(member, topic, {}, "", url);
        expect(second.status).toBe(429);
      } finally {
        await app.close();
      }
    });
  });

  describe("pool", () => {
    it("an open stream holds no pooled connection", async () => {
      const third = await makeUser(t);
      await addMember(t, owner, ws, third, "member");
      const pool = createPool(inject("dbUrl"));
      const app = buildApp({
        pool,
        config: t.config,
        sender: t.sender,
        clock: t.clock,
        blocklist: new Set(),
        logSink: (line) => appendFileSync(inject("logFile"), `${line}\n`),
      });
      try {
        await app.ready();
        const url = await listenOnFreePort(app);
        // 9 streams across 3 callers (3 each), more than the pool of 8.
        const streams: StreamClient[] = [];
        for (const who of [owner, member, third]) {
          for (let i = 0; i < 3; i += 1) {
            streams.push(await open(who, topic, {}, "", url));
          }
        }
        expect(streams.map((s) => s.status)).toEqual(Array(9).fill(200));

        // Eight requests at once all get a connection.
        const results = await Promise.all(
          Array.from({ length: 8 }, () =>
            app.inject({
              method: "GET",
              url: "/v1/workspaces",
              headers: bearer(owner.accessToken),
            }),
          ),
        );
        expect(results.map((r) => r.statusCode)).toEqual(Array(8).fill(200));

        // A live message still reaches every stream, by a short transaction.
        const sent = await app.inject({
          method: "POST",
          url: `/v1/topics/${topic}/messages`,
          headers: bearer(owner.accessToken),
          payload: { body: "to nine" },
        });
        expect(sent.statusCode).toBe(201);
        await until(() => streams.every((s) => seqs(s).length === 1), 5000);

        await sleep(200);
        expect(pool.totalCount - pool.idleCount).toBe(0);
        expect(pool.waitingCount).toBe(0);
      } finally {
        await app.close();
        await pool.end();
      }
    });
  });
});
