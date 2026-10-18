import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withContext } from "../../src/db.ts";
import {
  addMember,
  api,
  appWithHooks,
  bearer,
  createWorkspace,
  makeApp,
  makeUser,
  ownerPool,
  withAllWorkspaces,
} from "./harness.ts";
import type { TestApp, Tokens, User } from "./harness.ts";

// Each test holds one publish for 15 seconds, so each gets far more than the
// default.
const TIMEOUT = 60_000;
const HOLD_MS = 15_000;

interface Sent {
  seq: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// T-STALL: a publish that holds its topic's row lock stalls only the publishes
// to that topic. Publishes to other topics, in this workspace or another, go
// on. A waiter either gets its turn (long lock timeout) or a retryable 503
// `busy` (the 3 second timeout), and a retry with the same Idempotency-Key
// leaves one message.
describe("T-STALL", () => {
  let t: TestApp;
  let owner: User;
  let member: User;
  let other: User;
  let ws: string;
  let wsOther: string;
  let topicT: string;
  let topicV: string;
  let topicU: string;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    owner = await makeUser(t);
    member = await makeUser(t);
    other = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, member, "member");
    wsOther = await createWorkspace(t, other, "Other team");
    topicT = await makeTopic(ws, owner, "T");
    topicV = await makeTopic(ws, owner, "V");
    topicU = await makeTopic(wsOther, other, "U");
  });
  afterEach(() => t.close());

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

  function publish(
    app: TestApp["app"],
    who: Tokens,
    topicId: string,
    headers: Record<string, string> = {},
  ) {
    return app.inject({
      method: "POST",
      url: `/v1/topics/${topicId}/messages`,
      headers: { ...bearer(who.accessToken), ...headers },
      payload: { body: "stall test" },
    });
  }

  it("(i) a waiter with a 30 second lock timeout gets the next seq once the holder commits", async () => {
    const slow = await appWithHooks(t, { holdAfterSeqMs: HOLD_MS });
    const patient = await appWithHooks(t, { lockTimeoutMs: 30_000 });
    try {
      const a = publish(slow, owner, topicT);
      // Let A take its seq and start holding.
      await sleep(2000);
      const started = Date.now();
      const b = await publish(patient, member, topicT);
      const waited = Date.now() - started;
      const aResult = await a;

      expect(aResult.statusCode).toBe(201);
      expect(b.statusCode).toBe(201);
      expect(b.json<Sent>().seq).toBe(aResult.json<Sent>().seq + 1);
      // B really waited for A.
      expect(waited).toBeGreaterThan(5000);
    } finally {
      await slow.close();
      await patient.close();
    }
  }, TIMEOUT);

  it("(ii) with the 3 second timeout B gets 503 busy, other topics go on, and a retry makes one message", async () => {
    const slow = await appWithHooks(t, { holdAfterSeqMs: HOLD_MS });
    const strict = await appWithHooks(t, { lockTimeoutMs: 3000 });
    const db = ownerPool();
    try {
      let aDone = false;
      const a = publish(slow, owner, topicT).then((res) => {
        aDone = true;
        return res;
      });
      await sleep(2000);

      // B waits for the topic lock, gives up after 3 seconds, and is told to
      // retry.
      const key = { "idempotency-key": "stall-retry" };
      const b1 = await publish(strict, member, topicT, key);
      expect(b1.statusCode).toBe(503);
      expect(b1.json()).toEqual({ error: "busy" });
      // The rolled-back attempt freed the key.
      const claimed = await withAllWorkspaces(db, (c) =>
        c.query("SELECT 1 FROM idempotency_keys WHERE key = 'stall-retry'"),
      );
      expect(claimed.rows).toEqual([]);

      // C (topic U, another workspace) and C' (topic V, the same workspace as
      // T) are not stalled while A is held.
      const c = await publish(t.app, other, topicU);
      const cPrime = await publish(t.app, owner, topicV);
      expect(c.statusCode).toBe(201);
      expect(cPrime.statusCode).toBe(201);
      expect(aDone).toBe(false);

      const aResult = await a;
      expect(aResult.statusCode).toBe(201);

      // The retry, with the same key, after A has committed.
      const b2 = await publish(t.app, member, topicT, key);
      expect(b2.statusCode).toBe(201);
      expect(b2.json<Sent>().seq).toBe(aResult.json<Sent>().seq + 1);
      const again = await publish(t.app, member, topicT, key);
      expect(again.json()).toEqual(b2.json());

      // Exactly one message from B.
      const mine = await withContext(
        t.pool,
        { accountId: member.accountId },
        (tx) =>
          tx.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM messages
              WHERE topic_id = $1 AND sender_account_id = $2`,
            [topicT, member.accountId],
          ),
      );
      expect(mine.rows[0]?.n).toBe(1);
    } finally {
      await db.end();
      await slow.close();
      await strict.close();
    }
  }, TIMEOUT);
});
