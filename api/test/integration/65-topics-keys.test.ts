import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withContext, withKeyContext } from "../../src/db.ts";
import type { Db } from "../../src/db.ts";
import { hashToken } from "../../src/tokens.ts";
import {
  addMember,
  api,
  createWorkspace,
  makeApp,
  makeUser,
  registerSecret,
} from "./harness.ts";
import type { TestApp, User } from "./harness.ts";

interface Topic {
  id: string;
  workspace_id: string;
  name: string;
}

interface Made {
  id: string;
  topic_id: string;
  key: string;
  expires_at: string;
  rotated_id?: string;
}

interface KeyRow {
  id: string;
  topic_id: string;
  expires_at: string | null;
  revoked_at: string | null;
  rotated_at: string | null;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function parseKey(key: string): { id: string; secret: string } {
  const dot = key.indexOf(".");
  return { id: key.slice(0, dot), secret: key.slice(dot + 1) };
}

// Topics (A1) and the topic key lifecycle (A2). Keys are used through
// withKeyContext directly: HTTP key callers come with publish.
describe("topics and keys", () => {
  let t: TestApp;
  let owner: User;
  let admin: User;
  let member: User;
  let outsider: User;
  let ws: string;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    owner = await makeUser(t);
    admin = await makeUser(t);
    member = await makeUser(t);
    outsider = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, ws, admin, "admin");
    await addMember(t, owner, ws, member, "member");
  });
  afterEach(() => t.close());

  async function topic(name = "Alerts", who: User = owner): Promise<string> {
    const res = await api(t, who, "POST", `/v1/workspaces/${ws}/topics`, {
      name,
    });
    expect(res.statusCode).toBe(201);
    return res.json<Topic>().id;
  }

  async function newKey(topicId: string, who: User = owner): Promise<Made> {
    const res = await api(t, who, "POST", `/v1/topics/${topicId}/keys`);
    expect(res.statusCode).toBe(201);
    const made = res.json<Made>();
    registerSecret(made.key);
    registerSecret(parseKey(made.key).secret);
    return made;
  }

  // What a key resolves to through withKeyContext, or null.
  function resolve(key: string) {
    const { id, secret } = parseKey(key);
    return withKeyContext(t.pool, id, hashToken(secret), async (_tx, k) => k);
  }

  // Reads and changes rows as the owner of the workspace.
  function asOwner<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    return withContext(t.pool, { accountId: owner.accountId }, fn);
  }

  describe("topics", () => {
    it("creates, lists and trims", async () => {
      const res = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
        name: "  Build alerts  ",
      });
      expect(res.statusCode).toBe(201);
      const made = res.json<Topic>();
      expect(made).toEqual({
        id: expect.any(String),
        workspace_id: ws,
        name: "Build alerts",
      });
      // Any member may list.
      const list = await api(t, member, "GET", `/v1/workspaces/${ws}/topics`);
      expect(list.statusCode).toBe(200);
      expect(list.json<{ topics: Topic[] }>().topics).toEqual([
        expect.objectContaining({ id: made.id, name: "Build alerts" }),
      ]);
    });

    it("starts with last_seq 0 and oldest_kept_seq 1", async () => {
      const id = await topic();
      const row = await asOwner((tx) =>
        tx.query<{ last_seq: string; oldest_kept_seq: string }>(
          "SELECT last_seq, oldest_kept_seq FROM topics WHERE id = $1",
          [id],
        ),
      );
      expect(row.rows).toEqual([{ last_seq: "0", oldest_kept_seq: "1" }]);
    });

    it("refuses a bad name with 400, after the permission check", async () => {
      for (const name of ["", "   ", "x".repeat(61), 5, null]) {
        const res = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
          name,
        });
        expect(res.statusCode, JSON.stringify(name)).toBe(400);
      }
      const ok = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
        name: "x".repeat(60),
      });
      expect(ok.statusCode).toBe(201);
      // A member with a bad name learns nothing about the name rules.
      const denied = await api(
        t,
        member,
        "POST",
        `/v1/workspaces/${ws}/topics`,
        { name: "" },
      );
      expect(denied.statusCode).toBe(403);
    });

    it("needs topic.manage to create, and hides the workspace from outsiders", async () => {
      const asMember = await api(
        t,
        member,
        "POST",
        `/v1/workspaces/${ws}/topics`,
        { name: "No" },
      );
      expect(asMember.statusCode).toBe(403);
      const asAdmin = await api(
        t,
        admin,
        "POST",
        `/v1/workspaces/${ws}/topics`,
        { name: "Yes" },
      );
      expect(asAdmin.statusCode).toBe(201);
      const create = await api(
        t,
        outsider,
        "POST",
        `/v1/workspaces/${ws}/topics`,
        { name: "No" },
      );
      expect(create.statusCode).toBe(404);
      const list = await api(
        t,
        outsider,
        "GET",
        `/v1/workspaces/${ws}/topics`,
      );
      expect(list.statusCode).toBe(404);
    });

    it("T-LIMITS: the fourth topic is refused, and a delete frees a slot", async () => {
      const first = await topic("One");
      await topic("Two");
      await topic("Three");
      const over = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
        name: "Four",
      });
      expect(over.statusCode).toBe(409);
      expect(over.json()).toEqual({ error: "topic_limit" });
      const removed = await api(t, owner, "DELETE", `/v1/topics/${first}`);
      expect(removed.statusCode).toBe(204);
      const again = await api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
        name: "Four",
      });
      expect(again.statusCode).toBe(201);
    });

    it("T-LIMITS: concurrent creates cannot pass the limit", async () => {
      const results = await Promise.all(
        [1, 2, 3, 4, 5, 6].map((n) =>
          api(t, owner, "POST", `/v1/workspaces/${ws}/topics`, {
            name: `T${n}`,
          }),
        ),
      );
      const codes = results.map((r) => r.statusCode).sort();
      expect(codes).toEqual([201, 201, 201, 409, 409, 409]);
    });

    it("renames and deletes with topic.manage only", async () => {
      const id = await topic();
      const asMember = await api(t, member, "PATCH", `/v1/topics/${id}`, {
        name: "Mine",
      });
      expect(asMember.statusCode).toBe(403);
      const asOutsider = await api(t, outsider, "PATCH", `/v1/topics/${id}`, {
        name: "Mine",
      });
      expect(asOutsider.statusCode).toBe(404);
      const bad = await api(t, admin, "PATCH", `/v1/topics/${id}`, {
        name: "",
      });
      expect(bad.statusCode).toBe(400);
      const renamed = await api(t, admin, "PATCH", `/v1/topics/${id}`, {
        name: "  Renamed ",
      });
      expect(renamed.statusCode).toBe(200);
      expect(renamed.json()).toEqual({ id, name: "Renamed" });

      expect(
        (await api(t, member, "DELETE", `/v1/topics/${id}`)).statusCode,
      ).toBe(403);
      expect(
        (await api(t, outsider, "DELETE", `/v1/topics/${id}`)).statusCode,
      ).toBe(404);
      expect(
        (await api(t, admin, "DELETE", `/v1/topics/${id}`)).statusCode,
      ).toBe(204);
      expect(
        (await api(t, admin, "DELETE", `/v1/topics/${id}`)).statusCode,
      ).toBe(404);
    });

    it("an unknown or malformed topic id is 404", async () => {
      for (const id of [randomUUID(), "not-a-uuid"]) {
        expect(
          (await api(t, owner, "PATCH", `/v1/topics/${id}`, { name: "x" }))
            .statusCode,
        ).toBe(404);
        expect(
          (await api(t, owner, "DELETE", `/v1/topics/${id}`)).statusCode,
        ).toBe(404);
        expect(
          (await api(t, owner, "POST", `/v1/topics/${id}/keys`)).statusCode,
        ).toBe(404);
      }
    });

    it("another workspace's owner cannot reach the topic", async () => {
      const id = await topic();
      const other = await createWorkspace(t, outsider, "Theirs");
      const mine = await api(
        t,
        outsider,
        "POST",
        `/v1/workspaces/${other}/topics`,
        { name: "Theirs" },
      );
      expect(mine.statusCode).toBe(201);
      const renamed = await api(t, outsider, "PATCH", `/v1/topics/${id}`, {
        name: "Taken",
      });
      expect(renamed.statusCode).toBe(404);
      const keyed = await api(t, outsider, "POST", `/v1/topics/${id}/keys`);
      expect(keyed.statusCode).toBe(404);
      const still = await asOwner((tx) =>
        tx.query<{ name: string }>("SELECT name FROM topics WHERE id = $1", [
          id,
        ]),
      );
      expect(still.rows).toEqual([{ name: "Alerts" }]);
    });

    it("deleting a topic removes its keys", async () => {
      const id = await topic();
      const made = await newKey(id);
      await api(t, owner, "DELETE", `/v1/topics/${id}`);
      expect(await resolve(made.key)).toBeNull();
      const left = await asOwner((tx) =>
        tx.query("SELECT 1 FROM topic_keys WHERE topic_id = $1", [id]),
      );
      expect(left.rowCount).toBe(0);
    });
  });

  describe("keys", () => {
    it("returns the key once, with a 365-day expiry, and stores only the hash", async () => {
      const topicId = await topic();
      const before = Date.now();
      const made = await newKey(topicId);
      expect(made.key).toMatch(/^pz_[a-z2-7]{8}\.[A-Za-z0-9_-]{43}$/);
      expect(made.topic_id).toBe(topicId);
      const { id, secret } = parseKey(made.key);
      expect(id).toBe(made.id);
      const expires = new Date(made.expires_at).getTime();
      expect(expires).toBeGreaterThan(before + 364 * DAY_MS);
      expect(expires).toBeLessThan(Date.now() + 366 * DAY_MS);

      const stored = await asOwner((tx) =>
        tx.query<{ key_hash: Buffer; whole: string }>(
          `SELECT key_hash, row_to_json(k)::text AS whole
             FROM topic_keys k WHERE id = $1`,
          [id],
        ),
      );
      expect(stored.rows).toHaveLength(1);
      expect(stored.rows[0]?.key_hash.equals(hashToken(secret))).toBe(true);
      // No column holds the secret or the whole key.
      expect(stored.rows[0]?.whole).not.toContain(secret);
      expect(stored.rows[0]?.whole).not.toContain(made.key);

      // It is not in the list, and the list has no hash.
      const list = await api(t, owner, "GET", `/v1/workspaces/${ws}/keys`);
      expect(list.statusCode).toBe(200);
      expect(list.body).not.toContain(secret);
      expect(list.body).not.toMatch(/hash/i);
      expect(list.json<{ keys: KeyRow[] }>().keys).toEqual([
        {
          id,
          topic_id: topicId,
          created_at: expect.any(String),
          expires_at: made.expires_at,
          revoked_at: null,
          rotated_at: null,
        },
      ]);
    });

    it("works only on its own topic and workspace", async () => {
      const one = await topic("One");
      const two = await topic("Two");
      const made = await newKey(one);
      const other = await createWorkspace(t, outsider, "Theirs");
      const foreign = await api(
        t,
        outsider,
        "POST",
        `/v1/workspaces/${other}/topics`,
        { name: "Foreign" },
      );
      const foreignId = foreign.json<Topic>().id;

      const { id, secret } = parseKey(made.key);
      const seen = await withKeyContext(
        t.pool,
        id,
        hashToken(secret),
        async (tx, key) => {
          const topics = await tx.query<{ id: string }>(
            "SELECT id FROM topics ORDER BY id",
          );
          return { key, topics: topics.rows.map((r) => r.id).sort() };
        },
      );
      expect(seen?.key).toEqual({ topicId: one, workspaceId: ws });
      expect(seen?.key.topicId).not.toBe(two);
      // The context holds the workspace, not the topic: the other topic of the
      // same workspace is visible to the rows, the foreign one is not. What
      // pins the key to one topic is the topic id that resolve returns.
      expect(seen?.topics).toEqual([one, two].sort());
      expect(seen?.topics).not.toContain(foreignId);
    });

    it("does not resolve with a wrong secret or a wrong id", async () => {
      const made = await newKey(await topic());
      const { id } = parseKey(made.key);
      expect(await resolve(`${id}.${"A".repeat(43)}`)).toBeNull();
      const { secret } = parseKey(made.key);
      expect(await resolve(`pz_aaaaaaaa.${secret}`)).toBeNull();
    });

    it("needs key.manage, and hides the topic from outsiders", async () => {
      const topicId = await topic();
      const keysUrl = `/v1/topics/${topicId}/keys`;
      const asMember = await api(t, member, "POST", keysUrl);
      expect(asMember.statusCode).toBe(403);
      const asOutsider = await api(t, outsider, "POST", keysUrl);
      expect(asOutsider.statusCode).toBe(404);
      const asAdmin = await newKey(topicId, admin);
      expect(asAdmin.topic_id).toBe(topicId);
      const listUrl = `/v1/workspaces/${ws}/keys`;
      const listMember = await api(t, member, "GET", listUrl);
      expect(listMember.statusCode).toBe(403);
      const listOutsider = await api(t, outsider, "GET", listUrl);
      expect(listOutsider.statusCode).toBe(404);
    });

    it("revoking takes effect at once, and a repeat keeps the first time", async () => {
      const topicId = await topic();
      const made = await newKey(topicId);
      expect(await resolve(made.key)).not.toBeNull();

      expect(
        (await api(t, member, "DELETE", `/v1/keys/${made.id}`)).statusCode,
      ).toBe(403);
      expect(
        (await api(t, outsider, "DELETE", `/v1/keys/${made.id}`)).statusCode,
      ).toBe(404);
      expect(await resolve(made.key)).not.toBeNull();

      const gone = await api(t, admin, "DELETE", `/v1/keys/${made.id}`);
      expect(gone.statusCode).toBe(204);
      expect(await resolve(made.key)).toBeNull();

      const read = () =>
        asOwner((tx) =>
          tx.query<{ revoked_at: Date }>(
            "SELECT revoked_at FROM topic_keys WHERE id = $1",
            [made.id],
          ),
        );
      const firstTime = (await read()).rows[0]?.revoked_at;
      expect(firstTime).toBeInstanceOf(Date);
      const again = await api(t, admin, "DELETE", `/v1/keys/${made.id}`);
      expect(again.statusCode).toBe(204);
      expect((await read()).rows[0]?.revoked_at).toEqual(firstTime);

      expect(
        (await api(t, owner, "DELETE", `/v1/keys/pz_aaaaaaaa`)).statusCode,
      ).toBe(404);
      expect(
        (await api(t, owner, "DELETE", `/v1/keys/not-a-key`)).statusCode,
      ).toBe(404);
    });

    it("an expired key fails at once, and cannot be rotated", async () => {
      const made = await newKey(await topic());
      await asOwner((tx) =>
        tx.query(
          "UPDATE topic_keys SET expires_at = now() - interval '1 minute' WHERE id = $1",
          [made.id],
        ),
      );
      expect(await resolve(made.key)).toBeNull();
      const rotated = await api(t, owner, "POST", `/v1/keys/${made.id}/rotate`);
      expect(rotated.statusCode).toBe(409);
    });

    it("rotation: a new key on the same topic, the old one valid for at most 24 hours", async () => {
      const topicId = await topic();
      const old = await newKey(topicId);
      const res = await api(t, admin, "POST", `/v1/keys/${old.id}/rotate`);
      expect(res.statusCode).toBe(201);
      const fresh = res.json<Made>();
      registerSecret(fresh.key);
      registerSecret(parseKey(fresh.key).secret);
      expect(fresh.rotated_id).toBe(old.id);
      expect(fresh.id).not.toBe(old.id);
      expect(fresh.topic_id).toBe(topicId);

      // Both resolve to the same topic during the overlap.
      expect((await resolve(old.key))?.topicId).toBe(topicId);
      expect((await resolve(fresh.key))?.topicId).toBe(topicId);

      const row = await asOwner((tx) =>
        tx.query<{
          rotated: boolean;
          within_a_day: boolean;
          still_open: boolean;
          fresh_rotated: Date | null;
        }>(
          `SELECT o.rotated_at IS NOT NULL AS rotated,
                  o.expires_at <= now() + interval '24 hours' AS within_a_day,
                  o.expires_at > now() AS still_open,
                  n.rotated_at AS fresh_rotated
             FROM topic_keys o, topic_keys n
            WHERE o.id = $1 AND n.id = $2`,
          [old.id, fresh.id],
        ),
      );
      expect(row.rows).toEqual([
        {
          rotated: true,
          within_a_day: true,
          still_open: true,
          fresh_rotated: null,
        },
      ]);

      // The overlap ends at expires_at.
      await asOwner((tx) =>
        tx.query(
          "UPDATE topic_keys SET expires_at = now() - interval '1 second' WHERE id = $1",
          [old.id],
        ),
      );
      expect(await resolve(old.key)).toBeNull();
      expect(await resolve(fresh.key)).not.toBeNull();
    });

    it("rotation keeps a shorter expiry and gives a key with none a 24-hour end", async () => {
      const topicId = await topic();
      const soon = await newKey(topicId);
      await asOwner((tx) =>
        tx.query(
          "UPDATE topic_keys SET expires_at = now() + interval '1 hour' WHERE id = $1",
          [soon.id],
        ),
      );
      expect(
        (await api(t, owner, "POST", `/v1/keys/${soon.id}/rotate`)).statusCode,
      ).toBe(201);
      const kept = await asOwner((tx) =>
        tx.query<{ short: boolean }>(
          "SELECT expires_at <= now() + interval '1 hour' AS short FROM topic_keys WHERE id = $1",
          [soon.id],
        ),
      );
      expect(kept.rows[0]?.short).toBe(true);

      const forever = await newKey(topicId);
      await asOwner((tx) =>
        tx.query("UPDATE topic_keys SET expires_at = NULL WHERE id = $1", [
          forever.id,
        ]),
      );
      expect(
        (await api(t, owner, "POST", `/v1/keys/${forever.id}/rotate`))
          .statusCode,
      ).toBe(201);
      const capped = await asOwner((tx) =>
        tx.query<{ ok: boolean }>(
          `SELECT expires_at IS NOT NULL AND expires_at <= now() + interval '24 hours' AS ok
             FROM topic_keys WHERE id = $1`,
          [forever.id],
        ),
      );
      expect(capped.rows[0]?.ok).toBe(true);
    });

    it("a rotated, revoked or unknown key cannot be rotated", async () => {
      const topicId = await topic();
      const rotated = await newKey(topicId);
      expect(
        (await api(t, owner, "POST", `/v1/keys/${rotated.id}/rotate`))
          .statusCode,
      ).toBe(201);
      const rotateUrl = `/v1/keys/${rotated.id}/rotate`;
      const again = await api(t, owner, "POST", rotateUrl);
      expect(again.statusCode).toBe(409);

      const revoked = await newKey(topicId);
      await api(t, owner, "DELETE", `/v1/keys/${revoked.id}`);
      const afterRevoke = await api(
        t,
        owner,
        "POST",
        `/v1/keys/${revoked.id}/rotate`,
      );
      expect(afterRevoke.statusCode).toBe(409);

      const live = await newKey(topicId);
      expect(
        (await api(t, member, "POST", `/v1/keys/${live.id}/rotate`)).statusCode,
      ).toBe(403);
      expect(
        (await api(t, outsider, "POST", `/v1/keys/${live.id}/rotate`))
          .statusCode,
      ).toBe(404);
      expect(
        (await api(t, owner, "POST", `/v1/keys/pz_aaaaaaaa/rotate`)).statusCode,
      ).toBe(404);
    });

    it("T-LIMITS: the sixth key is refused; rotation works at the cap; revoking frees a slot", async () => {
      const topicId = await topic();
      const keys: Made[] = [];
      for (let n = 0; n < 5; n += 1) keys.push(await newKey(topicId));
      const over = await api(t, owner, "POST", `/v1/topics/${topicId}/keys`);
      expect(over.statusCode).toBe(409);
      expect(over.json()).toEqual({ error: "key_limit" });

      // At the cap, a rotation still works: the old key stops counting.
      const first = keys[0] as Made;
      const firstUrl = `/v1/keys/${first.id}/rotate`;
      const rotated = await api(t, owner, "POST", firstUrl);
      expect(rotated.statusCode).toBe(201);
      registerSecret(rotated.json<Made>().key);
      // The count is 5 again, so a new key is still refused.
      const stillOver = await api(
        t,
        owner,
        "POST",
        `/v1/topics/${topicId}/keys`,
      );
      expect(stillOver.statusCode).toBe(409);
      // Rotating again, at the cap, works too.
      const second = keys[1] as Made;
      expect(
        (await api(t, owner, "POST", `/v1/keys/${second.id}/rotate`))
          .statusCode,
      ).toBe(201);

      const revoked = keys[2] as Made;
      await api(t, owner, "DELETE", `/v1/keys/${revoked.id}`);
      const room = await api(t, owner, "POST", `/v1/topics/${topicId}/keys`);
      expect(room.statusCode).toBe(201);
      registerSecret(room.json<Made>().key);
    });

    it("T-LIMITS: the key limit is per workspace, across topics", async () => {
      const one = await topic("One");
      const two = await topic("Two");
      for (let n = 0; n < 3; n += 1) await newKey(one);
      for (let n = 0; n < 2; n += 1) await newKey(two);
      const over = await api(t, owner, "POST", `/v1/topics/${two}/keys`);
      expect(over.statusCode).toBe(409);
    });

    it("T-LIMITS: concurrent key creates cannot pass the limit", async () => {
      const topicId = await topic();
      const results = await Promise.all(
        [1, 2, 3, 4, 5, 6, 7].map(() =>
          api(t, owner, "POST", `/v1/topics/${topicId}/keys`),
        ),
      );
      for (const res of results) {
        if (res.statusCode === 201) registerSecret(res.json<Made>().key);
      }
      const codes = results.map((r) => r.statusCode).sort();
      expect(codes).toEqual([201, 201, 201, 201, 201, 409, 409]);
    });
  });
});
