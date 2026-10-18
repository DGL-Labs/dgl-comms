import type { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  addMember,
  api,
  bearer,
  createWorkspace,
  makeApp,
  makeUser,
  ownerPool,
  withAllWorkspaces,
} from "./harness.ts";
import type { TestApp, Tokens, User } from "./harness.ts";

interface Polled {
  messages: { seq: number; body: string }[];
  gaps: { from: number; to: number }[];
  next: number;
}

// The long-poll fallback (B6): off by default, and with the flag on the same
// access, RLS path, gap rule and limits as the stream.
describe("long-poll", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let member: User;
  let other: User;
  let ws: string;
  let topic: string;

  async function setUp(longPollOn: boolean): Promise<void> {
    t = await makeApp({ allowlistOn: false, longPollOn });
    db = ownerPool();
    owner = await makeUser(t);
    member = await makeUser(t);
    other = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    const made = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
      name: "Alerts",
    });
    expect(made.statusCode).toBe(201);
    topic = made.json<{ id: string }>().id;
  }

  afterEach(async () => {
    await db.end();
    await t.close();
  });

  function poll(who: Tokens, query: string, topicId = topic) {
    return t.app.inject({
      method: "GET",
      url: `/v1/topics/${topicId}/messages${query}`,
      headers: bearer(who.accessToken),
    });
  }

  async function publish(body: string): Promise<void> {
    const res = await api(t, owner, "POST", `/v1/topics/${topic}/messages`, {
      body,
    });
    expect(res.statusCode).toBe(201);
  }

  describe("flag off (the default)", () => {
    beforeEach(() => setUp(false));

    it("is not there", async () => {
      expect((await poll(member, "?since=0&wait=0")).statusCode).toBe(404);
    });
  });

  describe("flag on", () => {
    beforeEach(() => setUp(true));

    it("returns what is already there after since, in seq order", async () => {
      await publish("one");
      await publish("two");
      await publish("three");
      const res = await poll(member, "?since=1&wait=0");
      expect(res.statusCode).toBe(200);
      expect(res.headers["cache-control"]).toBe("no-store");
      const body = res.json<Polled>();
      expect(body.messages.map((m) => [m.seq, m.body])).toEqual([
        [2, "two"],
        [3, "three"],
      ]);
      expect(body.gaps).toEqual([]);
      expect(body.next).toBe(3);
    });

    it("waits, and answers as soon as a message is published", async () => {
      const started = Date.now();
      const pending = poll(member, "?since=0&wait=10");
      await new Promise((resolve) => setTimeout(resolve, 300));
      await publish("late");
      const res = await pending;
      expect(res.statusCode).toBe(200);
      expect(res.json<Polled>().messages.map((m) => m.body)).toEqual(["late"]);
      expect(Date.now() - started).toBeLessThan(5000);
    });

    it("answers empty when the wait runs out", async () => {
      const res = await poll(member, "?since=0&wait=1");
      expect(res.statusCode).toBe(200);
      expect(res.json<Polled>()).toEqual({ messages: [], gaps: [], next: 0 });
    });

    it("sends the gap rule's gaps", async () => {
      for (let n = 1; n <= 4; n += 1) await publish(`m${n}`);
      await withAllWorkspaces(db, (c) =>
        c.query("UPDATE topics SET oldest_kept_seq = 3 WHERE id = $1", [topic]),
      );
      const body = (await poll(member, "?since=0&wait=0")).json<Polled>();
      expect(body.gaps).toEqual([{ from: 1, to: 2 }]);
      expect(body.messages.map((m) => m.seq)).toEqual([3, 4]);
      expect(body.next).toBe(4);
    });

    it("rejects a bad since or wait with 400", async () => {
      for (const query of ["", "?since=-1", "?since=x", "?since=0&wait=26"]) {
        expect((await poll(member, query)).statusCode, query).toBe(400);
      }
    });

    it("refuses a topic key with 401 and a key in the query with 400", async () => {
      const made = await api(t, owner, "POST", `/v1/topics/${topic}/keys`);
      const key = made.json<{ key: string }>().key;
      const byKey = await t.app.inject({
        method: "GET",
        url: `/v1/topics/${topic}/messages?since=0&wait=0`,
        headers: { authorization: `Bearer ${key}` },
      });
      expect(byKey.statusCode).toBe(401);
      expect(
        (await poll(member, `?since=0&wait=0&key=${encodeURIComponent(key)}`))
          .statusCode,
      ).toBe(400);
    });

    it("gives a non-member 404", async () => {
      expect((await poll(other, "?since=0&wait=0")).statusCode).toBe(404);
    });

    it("refuses a suspended workspace with 404", async () => {
      await withAllWorkspaces(db, (c) =>
        c.query("UPDATE workspaces SET status = 'suspended' WHERE id = $1", [
          ws,
        ]),
      );
      expect((await poll(member, "?since=0&wait=0")).statusCode).toBe(404);
    });

    it("counts against the stream slots: the 4th waiting request gets 429", async () => {
      const waits = [1, 2, 3].map(() => poll(member, "?since=0&wait=3"));
      await new Promise((resolve) => setTimeout(resolve, 300));
      const fourth = await poll(member, "?since=0&wait=0");
      expect(fourth.statusCode).toBe(429);
      for (const res of await Promise.all(waits)) {
        expect(res.statusCode).toBe(200);
      }
      // The slots are free again.
      expect((await poll(member, "?since=0&wait=0")).statusCode).toBe(200);
    });
  });
});
