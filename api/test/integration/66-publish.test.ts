import { randomUUID } from "node:crypto";
import pg from "pg";
import type { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, inject, it } from "vitest";
import { withContext } from "../../src/db.ts";
import type { Db } from "../../src/db.ts";
import {
  addMember,
  api,
  appWithHooks,
  bearer,
  createWorkspace,
  inContext,
  makeApp,
  makeUser,
  ownerPool,
  registerSecret,
  signup,
  uniqueEmail,
  withAllWorkspaces,
} from "./harness.ts";
import type { TestApp, Tokens, User } from "./harness.ts";

interface Sent {
  id: string;
  topic_id: string;
  seq: number;
}

interface SendOptions {
  payload?: object;
  headers?: Record<string, string>;
  query?: string;
  remoteAddress?: string;
}

let addrCounter = 0;

// A fresh client address, so the per-IP bucket of key callers is never shared
// between tests.
function addr(): string {
  addrCounter += 1;
  return `203.0.113.${(addrCounter % 250) + 1}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Publish (A3 to A5): limits, ceiling, pause flags, idempotency, preflight,
// HTTP key callers, the fanout job and the notification.
describe("publish", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let member: User;
  let outsider: User;
  let ws: string;
  let topic: string;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    db = ownerPool();
    owner = await makeUser(t);
    member = await makeUser(t);
    outsider = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    topic = await makeTopic(ws);
  });
  afterEach(async () => {
    // Put the service flags back, whatever a test did.
    await db.query(
      `UPDATE service_limits SET signup_paused = false,
              publish_paused_non_internal = false,
              max_msgs_per_day_total = 200000`,
    );
    await db.end();
    await t.close();
  });

  async function makeTopic(
    workspaceId: string,
    who: User = owner,
    name = "Alerts",
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

  async function makeKey(topicId: string, who: User = owner): Promise<string> {
    const res = await api(t, who, "POST", `/v1/topics/${topicId}/keys`);
    expect(res.statusCode).toBe(201);
    const { key } = res.json<{ key: string }>();
    registerSecret(key);
    registerSecret(key.slice(key.indexOf(".") + 1));
    return key;
  }

  function send(who: Tokens, topicId: string, options: SendOptions = {}) {
    return t.app.inject({
      method: "POST",
      url: `/v1/topics/${topicId}/messages${options.query ?? ""}`,
      headers: { ...bearer(who.accessToken), ...options.headers },
      payload: options.payload ?? { body: "hi" },
    });
  }

  function sendKey(key: string, topicId: string, options: SendOptions = {}) {
    return t.app.inject({
      method: "POST",
      url: `/v1/topics/${topicId}/messages${options.query ?? ""}`,
      remoteAddress: options.remoteAddress ?? addr(),
      headers: { authorization: `Bearer ${key}`, ...options.headers },
      payload: options.payload ?? { body: "hi" },
    });
  }

  function asOwner<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    return withContext(t.pool, { accountId: owner.accountId }, fn);
  }

  async function messageCount(topicId: string): Promise<number> {
    const res = await asOwner((tx) =>
      tx.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM messages WHERE topic_id = $1",
        [topicId],
      ),
    );
    return res.rows[0]?.n ?? -1;
  }

  async function setBucket(bucket: string, tokens: number): Promise<void> {
    await db.query(
      `INSERT INTO rate_buckets (bucket, tokens, updated_at)
       VALUES ($1, $2, now())
       ON CONFLICT (bucket) DO UPDATE
         SET tokens = EXCLUDED.tokens, updated_at = now()`,
      [bucket, tokens],
    );
  }

  async function readBucket(bucket: string): Promise<number | undefined> {
    const res = await db.query<{ tokens: number }>(
      "SELECT tokens::float8 AS tokens FROM rate_buckets WHERE bucket = $1",
      [bucket],
    );
    return res.rows[0]?.tokens;
  }

  async function makeInternal(workspaceId: string): Promise<void> {
    await withAllWorkspaces(db, (c) =>
      c.query("UPDATE workspaces SET kind = 'dgl_internal' WHERE id = $1", [
        workspaceId,
      ]),
    );
  }

  async function globalToday(): Promise<number> {
    const res = await db.query<{ n: number }>(
      `SELECT coalesce(sum(count), 0)::int AS n FROM global_usage_minute
        WHERE minute >= date_trunc('day', now())`,
    );
    return res.rows[0]?.n ?? -1;
  }

  describe("by session", () => {
    it("publishes with increasing seq, a sender, and one fanout job each", async () => {
      const sentinel = `body-${randomUUID()}`;
      registerSecret(sentinel);
      const one = await send(member, topic, {
        payload: { title: "Hello", body: sentinel },
      });
      expect(one.statusCode).toBe(201);
      expect(one.json<Sent>()).toEqual({
        id: expect.any(String),
        topic_id: topic,
        seq: 1,
      });
      const two = await send(member, topic, { payload: { body: "again" } });
      expect(two.json<Sent>().seq).toBe(2);

      const rows = await asOwner((tx) =>
        tx.query(
          `SELECT seq::int AS seq, sender_kind, sender_account_id, sender_key_id,
                  sender_label, title, body
             FROM messages WHERE topic_id = $1 ORDER BY seq`,
          [topic],
        ),
      );
      expect(rows.rows[0]).toEqual({
        seq: 1,
        sender_kind: "person",
        sender_account_id: member.accountId,
        sender_key_id: null,
        sender_label: "Member",
        title: "Hello",
        body: sentinel,
      });
      const jobs = await asOwner((tx) =>
        tx.query(
          `SELECT j.state, j.attempts, j.workspace_id
             FROM fanout_jobs j JOIN messages m ON m.id = j.message_id
            WHERE m.topic_id = $1 ORDER BY m.seq`,
          [topic],
        ),
      );
      expect(jobs.rows).toEqual([
        { state: "pending", attempts: 0, workspace_id: ws },
        { state: "pending", attempts: 0, workspace_id: ws },
      ]);
    });

    it("sends pg_notify with ids only, when the transaction commits", async () => {
      const listener = new pg.Client({ connectionString: inject("dbUrl") });
      await listener.connect();
      const seen: string[] = [];
      listener.on("notification", (message) => {
        if (message.payload !== undefined) seen.push(message.payload);
      });
      await listener.query("LISTEN pingzo_msg");
      try {
        const res = await send(member, topic, {
          payload: { body: "notify me" },
        });
        const expected = `${topic}:${res.json<Sent>().seq}`;
        for (let i = 0; i < 50 && !seen.includes(expected); i += 1) {
          await sleep(100);
        }
        expect(seen.filter((p) => p.startsWith(topic))).toEqual([expected]);
      } finally {
        await listener.end();
      }
    });

    it("needs a session: 401 without or with a bad token", async () => {
      const none = await t.app.inject({
        method: "POST",
        url: `/v1/topics/${topic}/messages`,
        payload: { body: "x" },
      });
      expect(none.statusCode).toBe(401);
      const bad = await t.app.inject({
        method: "POST",
        url: `/v1/topics/${topic}/messages`,
        headers: { authorization: "Bearer not-a-token" },
        payload: { body: "x" },
      });
      expect(bad.statusCode).toBe(401);
      expect(await messageCount(topic)).toBe(0);
    });

    it("gives 404 for an outsider and for an unknown topic, the same", async () => {
      const outside = await send(outsider, topic);
      const unknown = await send(owner, randomUUID());
      const notUuid = await send(owner, "not-a-uuid");
      expect(outside.statusCode).toBe(404);
      expect(unknown.statusCode).toBe(404);
      expect(notUuid.statusCode).toBe(404);
      expect(outside.json()).toEqual(unknown.json());
      expect(await messageCount(topic)).toBe(0);
    });

    it("with its permission check skipped, still reaches no other workspace", async () => {
      const broken = await appWithHooks(t, { skipPermissionChecks: true });
      try {
        const res = await broken.inject({
          method: "POST",
          url: `/v1/topics/${topic}/messages`,
          headers: bearer(outsider.accessToken),
          payload: { body: "x" },
        });
        expect(res.statusCode).toBe(404);
        expect(await messageCount(topic)).toBe(0);
      } finally {
        await broken.close();
      }
    });
  });

  describe("by key over HTTP", () => {
    it("publishes on its own topic as a key sender, and on no other", async () => {
      const key = await makeKey(topic);
      const keyId = key.slice(0, key.indexOf("."));
      const ok = await sendKey(key, topic, { payload: { body: "from key" } });
      expect(ok.statusCode).toBe(201);
      const rows = await asOwner((tx) =>
        tx.query(
          `SELECT sender_kind, sender_key_id, sender_account_id, sender_label
             FROM messages WHERE topic_id = $1`,
          [topic],
        ),
      );
      expect(rows.rows).toEqual([
        {
          sender_kind: "key",
          sender_key_id: keyId,
          sender_account_id: null,
          sender_label: keyId,
        },
      ]);

      // Another topic of the same workspace.
      const sibling = await makeTopic(ws, owner, "Other");
      const same = await sendKey(key, sibling);
      expect(same.statusCode).toBe(404);
      // A topic of another workspace, and one that does not exist: the same.
      const wsOther = await createWorkspace(t, outsider, "Other team");
      const foreign = await makeTopic(wsOther, outsider, "Theirs");
      const cross = await sendKey(key, foreign);
      const unknown = await sendKey(key, randomUUID());
      expect(cross.statusCode).toBe(404);
      expect(unknown.statusCode).toBe(404);
      expect(cross.json()).toEqual(unknown.json());
      expect(await messageCount(sibling)).toBe(0);
      // The foreign workspace was not charged.
      expect(await readBucket(`ws:${wsOther}`)).toBeUndefined();
    });

    it("refuses an expired key and a revoked key at once", async () => {
      const expired = await makeKey(topic);
      const revoked = await makeKey(topic);
      const expiredId = expired.slice(0, expired.indexOf("."));
      const revokedId = revoked.slice(0, revoked.indexOf("."));
      expect((await sendKey(expired, topic)).statusCode).toBe(201);
      expect((await sendKey(revoked, topic)).statusCode).toBe(201);

      await withAllWorkspaces(db, (c) =>
        c.query(
          "UPDATE topic_keys SET expires_at = now() - interval '1 second' WHERE id = $1",
          [expiredId],
        ),
      );
      const gone = await api(t, owner, "DELETE", `/v1/keys/${revokedId}`);
      expect(gone.statusCode).toBe(204);

      const a = await sendKey(expired, topic);
      const b = await sendKey(revoked, topic);
      expect(a.statusCode).toBe(401);
      expect(b.statusCode).toBe(401);
      expect(await messageCount(topic)).toBe(2);
    });

    it("refuses a malformed or wrong key with 401", async () => {
      const key = await makeKey(topic);
      const id = key.slice(0, key.indexOf("."));
      const wrongSecret = `${id}.${"A".repeat(43)}`;
      const unknownId = `pz_${"a".repeat(8)}.${"A".repeat(43)}`;
      for (const bad of [wrongSecret, unknownId, `${id}`, `${id}.short`]) {
        const res = await sendKey(bad, topic);
        expect(res.statusCode, bad).toBe(401);
      }
      expect(await messageCount(topic)).toBe(0);
    });

    it("refuses a key in the query string with 400", async () => {
      const key = await makeKey(topic);
      const asQuery = await sendKey(key, topic, { query: `?key=${key}` });
      expect(asQuery.statusCode).toBe(400);
      const hidden = await sendKey(key, topic, { query: "?x=pz_abcdefgh" });
      expect(hidden.statusCode).toBe(400);
      const named = await send(member, topic, { query: "?access_token=abc" });
      expect(named.statusCode).toBe(400);
      expect(await messageCount(topic)).toBe(0);
      // The same key in the header still works.
      expect((await sendKey(key, topic)).statusCode).toBe(201);
    });
  });

  describe("T-LIMITS (publish)", () => {
    it("takes 2,048 bytes and refuses 2,049, counting bytes", async () => {
      const ok = await send(member, topic, {
        payload: { body: "a".repeat(2048) },
      });
      expect(ok.statusCode).toBe(201);
      const over = await send(member, topic, {
        payload: { body: "a".repeat(2049) },
      });
      expect(over.statusCode).toBe(413);
      // 1,024 two-byte characters are 2,048 bytes; one more byte is too many.
      const wide = await send(member, topic, {
        payload: { body: "é".repeat(1024) },
      });
      expect(wide.statusCode).toBe(201);
      const wideOver = await send(member, topic, {
        payload: { body: `${"é".repeat(1024)}a` },
      });
      expect(wideOver.statusCode).toBe(413);
      const fewChars = await send(member, topic, {
        payload: { body: "é".repeat(1025) },
      });
      expect(fewChars.statusCode).toBe(413);
      expect(await messageCount(topic)).toBe(2);
    });

    it("takes a title of 120 characters and refuses 121", async () => {
      const ok = await send(member, topic, {
        payload: { title: "t".repeat(120), body: "x" },
      });
      expect(ok.statusCode).toBe(201);
      const over = await send(member, topic, {
        payload: { title: "t".repeat(121), body: "x" },
      });
      expect(over.statusCode).toBe(400);
      const lines = await send(member, topic, {
        payload: { title: "a\nb", body: "x" },
      });
      expect(lines.statusCode).toBe(400);
    });

    it("refuses a missing, empty, non-text or NUL body with 400", async () => {
      for (const payload of [
        {},
        { body: "" },
        { body: 5 },
        { body: "a\u0000b" },
        { body: "x", title: 5 },
        [],
      ]) {
        const res = await send(member, topic, { payload });
        expect(res.statusCode, JSON.stringify(payload)).toBe(400);
      }
      expect(await messageCount(topic)).toBe(0);
    });

    it("keeps the caller and workspace buckets at 60, filled on first use", async () => {
      await send(member, topic);
      const caller = await readBucket(`acct:${member.accountId}`);
      const workspace = await readBucket(`ws:${ws}`);
      expect(caller).toBeGreaterThan(58);
      expect(caller).toBeLessThanOrEqual(59);
      expect(workspace).toBeGreaterThan(58);
      expect(workspace).toBeLessThanOrEqual(59);
    });

    it("answers 429 when the caller bucket is empty", async () => {
      await setBucket(`acct:${member.accountId}`, 1);
      expect((await send(member, topic)).statusCode).toBe(201);
      const res = await send(member, topic);
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ error: "rate_limited" });
      expect(await messageCount(topic)).toBe(1);
    });

    it("answers 429 when the workspace bucket is empty", async () => {
      await setBucket(`ws:${ws}`, 2);
      expect((await send(member, topic)).statusCode).toBe(201);
      expect((await send(owner, topic)).statusCode).toBe(201);
      const res = await send(member, topic);
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ error: "workspace_rate_limited" });
      expect(await messageCount(topic)).toBe(2);
    });

    it("answers 429 at 1,000 a day, and counts per workspace", async () => {
      await db.query(
        `INSERT INTO workspace_usage_daily (workspace_id, day, count)
         VALUES ($1, current_date, 999)`,
        [ws],
      );
      expect((await send(member, topic)).statusCode).toBe(201);
      const res = await send(member, topic);
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ error: "daily_limit" });
      const count = await db.query<{ count: number }>(
        "SELECT count FROM workspace_usage_daily WHERE workspace_id = $1",
        [ws],
      );
      expect(count.rows[0]?.count).toBe(1000);
      // Another workspace is not affected.
      const wsOther = await createWorkspace(t, outsider, "Other team");
      const other = await makeTopic(wsOther, outsider, "Theirs");
      expect((await send(outsider, other)).statusCode).toBe(201);
    });

    it("charges every key attempt, good or bad, to its IP bucket", async () => {
      const key = await makeKey(topic);
      const id = key.slice(0, key.indexOf("."));
      const bad = `${id}.${"A".repeat(43)}`;
      const address = addr();
      await setBucket(`ip:${address}`, 2);
      const first = await sendKey(bad, topic, { remoteAddress: address });
      expect(first.statusCode).toBe(401);
      const second = await sendKey(key, topic, { remoteAddress: address });
      expect(second.statusCode).toBe(201);
      const third = await sendKey(key, topic, { remoteAddress: address });
      expect(third.statusCode).toBe(429);
      expect(third.json()).toEqual({ error: "rate_limited" });
    });
  });

  describe("preflight", () => {
    it("charges a refused caller only to its own bucket, never to the workspace", async () => {
      // Nothing has been published in ws yet: no workspace counters exist.
      const wsBucket = `ws:${ws}`;
      expect(await readBucket(wsBucket)).toBeUndefined();

      const key = await makeKey(topic);
      const id = key.slice(0, key.indexOf("."));
      const refused = [
        await send(outsider, topic),
        await sendKey(`${id}.${"A".repeat(43)}`, topic),
        await send(outsider, randomUUID()),
      ];
      expect(refused.map((r) => r.statusCode)).toEqual([404, 401, 404]);

      expect(await readBucket(wsBucket)).toBeUndefined();
      const daily = await db.query(
        "SELECT 1 FROM workspace_usage_daily WHERE workspace_id = $1",
        [ws],
      );
      expect(daily.rows).toEqual([]);
      // The outsider's own bucket was charged, twice.
      const own = await readBucket(`acct:${outsider.accountId}`);
      expect(own).toBeLessThanOrEqual(58.5);
      // And nothing was published.
      expect(await messageCount(topic)).toBe(0);

      // A real publish does charge the workspace.
      expect((await send(member, topic)).statusCode).toBe(201);
      expect(await readBucket(wsBucket)).toBeLessThanOrEqual(59);
    });
  });

  describe("T-CEILING", () => {
    it("counts non-internal publishes only, and refuses them at the ceiling", async () => {
      const wsInternal = await createWorkspace(t, owner, "Internal");
      const internalTopic = await makeTopic(wsInternal, owner, "Ops");
      await makeInternal(wsInternal);

      const before = await globalToday();
      expect((await send(member, topic)).statusCode).toBe(201);
      expect(await globalToday()).toBe(before + 1);
      expect((await send(owner, internalTopic)).statusCode).toBe(201);
      expect(await globalToday()).toBe(before + 1);

      // The ceiling is the count so far plus one: one more passes, then 503.
      await db.query("UPDATE service_limits SET max_msgs_per_day_total = $1", [
        before + 2,
      ]);
      expect((await send(member, topic)).statusCode).toBe(201);
      const refused = await send(member, topic);
      expect(refused.statusCode).toBe(503);
      expect(refused.json()).toEqual({ error: "ceiling" });
      // A refusal is not counted, and dgl_internal still passes.
      expect(await globalToday()).toBe(before + 2);
      expect((await send(owner, internalTopic)).statusCode).toBe(201);
      const key = await makeKey(topic);
      expect((await sendKey(key, topic)).statusCode).toBe(503);
    });
  });

  describe("pause flags", () => {
    it("signup_paused gives 503 on sign-up and on workspace creation", async () => {
      await db.query("UPDATE service_limits SET signup_paused = true");
      const signed = await signup(t, uniqueEmail(), "198.51.100.200");
      expect(signed.statusCode).toBe(503);
      const created = await api(t, owner, "POST", "/v1/workspaces", {
        name: "Late",
        kind: "team",
      });
      expect(created.statusCode).toBe(503);
      // Everything else still works.
      expect((await send(member, topic)).statusCode).toBe(201);
      await db.query("UPDATE service_limits SET signup_paused = false");
      const again = await api(t, owner, "POST", "/v1/workspaces", {
        name: "Later",
        kind: "team",
      });
      expect(again.statusCode).toBe(201);
    });

    it("publish_paused_non_internal gives 503 for non-internal, and passes dgl_internal", async () => {
      const wsInternal = await createWorkspace(t, owner, "Internal");
      const internalTopic = await makeTopic(wsInternal, owner, "Ops");
      await makeInternal(wsInternal);
      const key = await makeKey(topic);

      await db.query(
        "UPDATE service_limits SET publish_paused_non_internal = true",
      );
      const session = await send(member, topic);
      expect(session.statusCode).toBe(503);
      const byKey = await sendKey(key, topic);
      expect(byKey.statusCode).toBe(503);
      expect((await send(owner, internalTopic)).statusCode).toBe(201);
      expect(await messageCount(topic)).toBe(0);

      await db.query(
        "UPDATE service_limits SET publish_paused_non_internal = false",
      );
      expect((await send(member, topic)).statusCode).toBe(201);
    });
  });

  describe("idempotency", () => {
    const key = (value: string) => ({ "idempotency-key": value });

    it("returns the first result for a repeat", async () => {
      const first = await send(member, topic, { headers: key("k-repeat") });
      const again = await send(member, topic, {
        headers: key("k-repeat"),
        payload: { body: "a different body" },
      });
      expect(first.statusCode).toBe(201);
      expect(again.statusCode).toBe(201);
      expect(again.json()).toEqual(first.json());
      expect(await messageCount(topic)).toBe(1);
    });

    it("makes one message for two concurrent duplicates", async () => {
      const [a, b] = await Promise.all([
        send(member, topic, { headers: key("k-race") }),
        send(member, topic, { headers: key("k-race") }),
      ]);
      expect(a.statusCode).toBe(201);
      expect(b.statusCode).toBe(201);
      expect(a.json()).toEqual(b.json());
      expect(await messageCount(topic)).toBe(1);
    });

    it("reuses a key older than 24 hours", async () => {
      const first = await send(member, topic, { headers: key("k-old") });
      await withAllWorkspaces(db, (c) =>
        c.query(
          `UPDATE idempotency_keys SET created_at = now() - interval '25 hours'
            WHERE key = 'k-old'`,
        ),
      );
      const second = await send(member, topic, { headers: key("k-old") });
      expect(second.statusCode).toBe(201);
      expect(second.json<Sent>().id).not.toBe(first.json<Sent>().id);
      expect(second.json<Sent>().seq).toBe(2);
      // The row now points at the new message.
      const row = await asOwner((tx) =>
        tx.query<{ message_id: string }>(
          "SELECT message_id FROM idempotency_keys WHERE key = 'k-old'",
        ),
      );
      expect(row.rows).toEqual([{ message_id: second.json<Sent>().id }]);
      // And inside 24 hours it is a repeat again.
      const repeat = await send(member, topic, { headers: key("k-old") });
      expect(repeat.json()).toEqual(second.json());
    });

    it("gives 409 for the same caller and key in another workspace", async () => {
      const wsTwo = await createWorkspace(t, owner, "Second");
      const topicTwo = await makeTopic(wsTwo, owner, "Two");
      const first = await send(owner, topic, { headers: key("k-cross") });
      expect(first.statusCode).toBe(201);
      const res = await send(owner, topicTwo, { headers: key("k-cross") });
      expect(res.statusCode).toBe(409);
      expect(res.json()).toEqual({ error: "idempotency_conflict" });
      expect(await messageCount(topicTwo)).toBe(0);
      // The key is still the first workspace's, and still replays there.
      const replay = await send(owner, topic, { headers: key("k-cross") });
      expect(replay.json()).toEqual(first.json());
    });

    it("gives 409 for the same caller and key on another topic", async () => {
      const sibling = await makeTopic(ws, owner, "Sibling");
      expect(
        (await send(member, topic, { headers: key("k-topic") })).statusCode,
      ).toBe(201);
      const res = await send(member, sibling, { headers: key("k-topic") });
      expect(res.statusCode).toBe(409);
      expect(await messageCount(sibling)).toBe(0);
    });

    it("keeps keys apart per caller, session or key", async () => {
      const apiKey = await makeKey(topic);
      const a = await send(member, topic, { headers: key("k-shared") });
      const b = await send(owner, topic, { headers: key("k-shared") });
      const c = await sendKey(apiKey, topic, { headers: key("k-shared") });
      for (const res of [a, b, c]) expect(res.statusCode).toBe(201);
      const ids = new Set([a, b, c].map((r) => r.json<Sent>().id));
      expect(ids.size).toBe(3);
      expect(await messageCount(topic)).toBe(3);
      // A key caller's repeat is a replay.
      const repeat = await sendKey(apiKey, topic, { headers: key("k-shared") });
      expect(repeat.json()).toEqual(c.json());
    });

    it("refuses a key of over 200 characters with 400, and takes 200", async () => {
      const long = await send(member, topic, { headers: key("k".repeat(201)) });
      expect(long.statusCode).toBe(400);
      const ok = await send(member, topic, { headers: key("k".repeat(200)) });
      expect(ok.statusCode).toBe(201);
    });

    it("stores nothing for a publish that is refused before the claim", async () => {
      const res = await send(member, topic, {
        headers: key("k-refused"),
        payload: { body: "" },
      });
      expect(res.statusCode).toBe(400);
      const rows = await db.query(
        "SELECT 1 FROM idempotency_keys WHERE key = 'k-refused'",
      );
      expect(rows.rows).toEqual([]);
      // So the key is free for a good request.
      const ok = await send(member, topic, { headers: key("k-refused") });
      expect(ok.statusCode).toBe(201);
    });
  });

  describe("T-RLS: idempotency_keys", () => {
    it("shows a context its own rows only, and refuses a write for another workspace", async () => {
      const wsB = await createWorkspace(t, outsider, "B");
      const topicB = await makeTopic(wsB, outsider, "B topic");
      expect(
        (await send(owner, topic, { headers: { "idempotency-key": "rls-a" } }))
          .statusCode,
      ).toBe(201);
      expect(
        (
          await send(outsider, topicB, {
            headers: { "idempotency-key": "rls-b" },
          })
        ).statusCode,
      ).toBe(201);

      const own = await inContext(t.pool, { workspaceIds: [ws] }, (c) =>
        c.query<{ key: string }>("SELECT key FROM idempotency_keys"),
      );
      expect(own.rows.map((r) => r.key)).toEqual(["rls-a"]);
      const none = await inContext(t.pool, {}, (c) =>
        c.query("SELECT key FROM idempotency_keys"),
      );
      expect(none.rows).toEqual([]);
      for (const raw of ["", "{}"]) {
        const empty = await inContext(t.pool, { raw }, (c) =>
          c.query("SELECT key FROM idempotency_keys"),
        );
        expect(empty.rows, raw).toEqual([]);
      }
      await expect(
        inContext(
          t.pool,
          { accountId: owner.accountId, workspaceIds: [ws] },
          (c) =>
            c.query(
              `INSERT INTO idempotency_keys (caller, key, workspace_id)
               VALUES ('a:x', 'rls-x', $1)`,
              [wsB],
            ),
        ),
      ).rejects.toThrow(/row-level security/);
    });
  });
});
