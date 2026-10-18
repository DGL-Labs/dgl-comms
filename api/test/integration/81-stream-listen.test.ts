import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  addMember,
  api,
  appWithHooks,
  backendsGone,
  bearer,
  createWorkspace,
  killListeners,
  listenOnFreePort,
  listenPids,
  makeApp,
  makeUser,
  openStream,
  ownerPool,
  sessionIdOf,
  withAllWorkspaces,
} from "./harness.ts";
import type { StreamClient, TestApp, Tokens, User } from "./harness.ts";

// A LISTEN reconnect delay that a test never reaches: LISTEN stays down.
const NEVER = 600_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function seqs(client: StreamClient): number[] {
  return client.events
    .filter((e) => e.event === "message")
    .map((e) => (JSON.parse(e.data) as { seq: number }).seq);
}

function range(from: number, to: number): number[] {
  return Array.from({ length: to - from + 1 }, (_, i) => from + i);
}

// The last event of a stream that the server ended: event: end, no id: line.
function endOf(client: StreamClient): { reason: string } | null {
  const last = client.events[client.events.length - 1];
  if (last === undefined || last.event !== "end" || last.id !== null) {
    return null;
  }
  return JSON.parse(last.data) as { reason: string };
}

// LISTEN outage (B4) and revocation (B5): the poll while LISTEN is down, the
// catch-up after it is back, and the streams that close when access changes.
describe("stream: LISTEN outage and revocation", () => {
  let t: TestApp;
  let db: Pool;
  let owner: User;
  let member: User;
  let ws: string;
  let topic: string;
  let apps: FastifyInstance[];
  let clients: StreamClient[];

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    db = ownerPool();
    owner = await makeUser(t);
    member = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    topic = await makeTopic(owner);
    apps = [];
    clients = [];
  });
  afterEach(async () => {
    for (const client of clients) client.close();
    for (const app of apps) await app.close();
    await db.end();
    await t.close();
  });

  async function makeTopic(who: User): Promise<string> {
    const res = await api(t, who, "POST", `/v1/workspaces/${ws}/topics`, {
      name: "Alerts",
    });
    expect(res.statusCode).toBe(201);
    return res.json<{ id: string }>().id;
  }

  // A second app on the same database, listening on a free port.
  async function startApp(
    hooks: Parameters<typeof appWithHooks>[1],
  ): Promise<string> {
    const app = await appWithHooks(t, hooks);
    apps.push(app);
    return listenOnFreePort(app);
  }

  async function open(
    url: string,
    who: Tokens,
    headers: Record<string, string> = {},
  ): Promise<StreamClient> {
    const client = await openStream(url, topic, {
      ...bearer(who.accessToken),
      ...headers,
    });
    clients.push(client);
    return client;
  }

  async function publish(who: Tokens, body = "hello"): Promise<number> {
    const res = await api(t, who, "POST", `/v1/topics/${topic}/messages`, {
      body,
    });
    expect(res.statusCode).toBe(201);
    return res.json<{ seq: number }>().seq;
  }

  // Kills the LISTEN backends and waits until they are gone.
  async function killListen(): Promise<void> {
    const pids = await killListeners(t.pool);
    expect(pids.length).toBeGreaterThan(0);
    await backendsGone(t.pool, pids);
  }

  describe("T-LISTEN", () => {
    it("loses no seq and repeats none when LISTEN is killed in a burst", async () => {
      const url = await startApp({ streamPollMs: 150, listenBackoffMs: 200 });
      const one = await open(url, owner);
      const two = await open(url, member);
      const before = await listenPids(t.pool);

      const total = 40;
      for (let i = 1; i <= total; i += 1) {
        await publish(i % 2 === 0 ? owner : member, `burst ${i}`);
        if (i === 15) await killListeners(t.pool);
      }
      await one.until(() => seqs(one).length >= total, 15_000);
      await two.until(() => seqs(two).length >= total, 15_000);
      await sleep(600);
      expect(seqs(one)).toEqual(range(1, total));
      expect(seqs(two)).toEqual(range(1, total));

      // LISTEN came back on a new connection, and delivery is live again.
      let fresh = false;
      const end = Date.now() + 10_000;
      while (!fresh && Date.now() < end) {
        fresh = (await listenPids(t.pool)).some((p) => !before.includes(p));
        if (!fresh) await sleep(100);
      }
      expect(fresh).toBe(true);
      await publish(owner, "after");
      await one.until(() => seqs(one).length >= total + 1, 5000);
      await sleep(300);
      expect(seqs(one)).toEqual(range(1, total + 1));
    });

    it("delivers by polling while LISTEN stays down", async () => {
      const url = await startApp({ streamPollMs: 200, listenBackoffMs: NEVER });
      const client = await open(url, owner);
      await killListen();
      await sleep(300);

      for (let i = 1; i <= 5; i += 1) await publish(member, `down ${i}`);
      await client.until(() => seqs(client).length >= 5, 5000);
      await sleep(600);
      expect(seqs(client)).toEqual(range(1, 5));

      // And it keeps going: another round, still polled.
      await publish(owner, "down 6");
      await client.until(() => seqs(client).length >= 6, 5000);
      await sleep(400);
      expect(seqs(client)).toEqual(range(1, 6));
    });

    it("catches up once LISTEN is back, with the poll too slow to matter", async () => {
      const url = await startApp({
        streamPollMs: NEVER,
        listenBackoffMs: 1500,
      });
      const client = await open(url, owner);
      await killListen();
      await sleep(300);

      for (let i = 1; i <= 4; i += 1) await publish(member, `gap ${i}`);
      await client.until(() => seqs(client).length >= 4, 10_000);
      await sleep(600);
      expect(seqs(client)).toEqual(range(1, 4));
    });
  });

  describe("event: end", () => {
    it("tells the client why when the server closes", async () => {
      const url = await startApp({});
      const client = await open(url, owner);
      expect(client.status).toBe(200);
      const app = apps.pop() as FastifyInstance;
      await app.close();
      await client.until(() => client.closed, 5000);
      expect(endOf(client)).toEqual({ reason: "server_closing" });
    });

    it("ends a stream when its access token expires", async () => {
      const url = await startApp({ streamRecheckMs: 300 });
      const client = await open(url, owner);
      const other = await open(url, member);
      expect(client.status).toBe(200);
      // The clock the app reads moves past the 15-minute token.
      t.clock.advance(16 * 60 * 1000);
      await client.until(() => client.closed, 5000);
      await other.until(() => other.closed, 5000);
      expect(endOf(client)).toEqual({ reason: "token_expired" });
      expect(endOf(other)).toEqual({ reason: "token_expired" });
    });
  });

  // Every trigger: LISTEN up (the hint closes it within 5 s, the re-check
  // interval is left at its default) and LISTEN down (the re-check closes it).
  const triggers: {
    name: string;
    // The streamer is the member; the owner's stream is the control.
    act: (ctx: Acting) => Promise<void>;
    // Whether the owner's stream closes too.
    ownerCloses: boolean;
  }[] = [
    {
      name: "member removal",
      act: async ({ t, ws, owner, member }) => {
        const res = await api(
          t,
          owner,
          "DELETE",
          `/v1/workspaces/${ws}/members/${member.accountId}`,
        );
        expect(res.statusCode).toBe(204);
      },
      ownerCloses: false,
    },
    {
      name: "session revoke (logout)",
      act: async ({ t, member }) => {
        const res = await api(t, member, "POST", "/v1/auth/logout");
        expect(res.statusCode).toBe(204);
      },
      ownerCloses: false,
    },
    {
      name: "account deletion",
      act: async ({ t, member }) => {
        const res = await api(t, member, "DELETE", "/v1/account");
        expect(res.statusCode).toBe(204);
      },
      ownerCloses: false,
    },
    {
      name: "topic delete",
      act: async ({ t, topic, owner }) => {
        const res = await api(t, owner, "DELETE", `/v1/topics/${topic}`);
        expect(res.statusCode).toBe(204);
      },
      ownerCloses: true,
    },
    {
      name: "workspace suspension",
      act: async ({ db, ws }) => {
        await withAllWorkspaces(db, (c) =>
          c.query("UPDATE workspaces SET status = 'suspended' WHERE id = $1", [
            ws,
          ]),
        );
      },
      ownerCloses: true,
    },
  ];

  interface Acting {
    t: TestApp;
    db: Pool;
    ws: string;
    topic: string;
    owner: User;
    member: User;
  }

  describe.each([
    { mode: "LISTEN up", down: false },
    { mode: "LISTEN down", down: true },
  ])("revocation, $mode", ({ down }) => {
    it.each(triggers)(
      "$name closes the affected stream",
      async ({ act, ownerCloses }) => {
        // Up: the default re-check interval, so only the hint can be in time.
        const hooks = down
          ? { streamRecheckMs: 1500, streamPollMs: 300, listenBackoffMs: NEVER }
          : { streamPollMs: 300, listenBackoffMs: 200 };
        const url = await startApp(hooks);
        const mine = await open(url, member);
        const control = await open(url, owner);
        expect(mine.status).toBe(200);
        expect(control.status).toBe(200);
        if (down) await killListen();
        await sleep(300);

        await act({ t, db, ws, topic, owner, member });
        // 5 s with the hint; the re-check interval plus slack without it.
        await mine.until(() => mine.closed, down ? 4000 : 5000);
        expect(endOf(mine)).toEqual({ reason: "revoked" });

        if (ownerCloses) {
          await control.until(() => control.closed, down ? 4000 : 5000);
          expect(endOf(control)).toEqual({ reason: "revoked" });
        } else {
          // Not affected: still open, and a message still gets to it.
          await sleep(down ? 2500 : 800);
          expect(control.closed).toBe(false);
          await publish(owner, "still here");
          await control.until(() => seqs(control).length === 1, 5000);
        }
      },
    );
  });

  describe("a hint is not a verdict", () => {
    it("a role change keeps the stream open", async () => {
      const url = await startApp({ streamPollMs: 300, listenBackoffMs: 200 });
      const mine = await open(url, member);
      expect(mine.status).toBe(200);
      for (const role of ["admin", "member"]) {
        const res = await api(
          t,
          owner,
          "PATCH",
          `/v1/workspaces/${ws}/members/${member.accountId}`,
          { role },
        );
        expect(res.statusCode).toBe(200);
        await sleep(1000);
        expect(mine.closed).toBe(false);
      }
      await publish(owner, "after the role change");
      await mine.until(() => seqs(mine).length === 1, 5000);
      expect(mine.closed).toBe(false);
    });

    it("a forged pingzo_acl notify closes nothing", async () => {
      const url = await startApp({ streamPollMs: 300, listenBackoffMs: 200 });
      const mine = await open(url, member);
      const control = await open(url, owner);
      const forge = (payload: string) =>
        t.pool.query("SELECT pg_notify('pingzo_acl', $1)", [payload]);
      await forge(`member:${ws}:${member.accountId}`);
      await forge(`member:${ws}:${owner.accountId}`);
      await forge(`session:${sessionIdOf(member.accessToken)}`);
      await forge(`session:${sessionIdOf(owner.accessToken)}`);
      await forge(`account:${member.accountId}`);
      await forge(`topic:${topic}`);
      await forge(`workspace:${ws}`);
      // Payloads that are not ids, and ids that are nobody's.
      await forge("garbage");
      await forge("topic:not-a-uuid");
      await forge("workspace:7b1f0c52-5a3e-4f58-9d52-0c1f3a9d4e11");
      await sleep(1500);

      expect(mine.closed).toBe(false);
      expect(control.closed).toBe(false);
      expect(mine.events).toEqual([]);
      await publish(owner, "still open");
      await mine.until(() => seqs(mine).length === 1, 5000);
      await control.until(() => seqs(control).length === 1, 5000);
    });

    it("refuses a stream on a suspended workspace with 404", async () => {
      await withAllWorkspaces(db, (c) =>
        c.query("UPDATE workspaces SET status = 'suspended' WHERE id = $1", [
          ws,
        ]),
      );
      const url = await startApp({});
      const refused = await open(url, member);
      await refused.until(() => refused.closed);
      expect(refused.status).toBe(404);
      expect(JSON.parse(refused.body)).toEqual({ error: "not_found" });
      const ownerRefused = await open(url, owner);
      expect(ownerRefused.status).toBe(404);
    });
  });
});
