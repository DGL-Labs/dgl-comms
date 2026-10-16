import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  addMember,
  api,
  createWorkspace,
  makeApp,
  makeUser,
  ownerPool,
} from "./harness.ts";
import type { TestApp, User } from "./harness.ts";

interface MemberList {
  members: { account_id: string; role: string }[];
}

// Workspaces, members and roles: cross-workspace deny, role deny, caps and the
// audit log.
describe("workspaces", () => {
  let t: TestApp;
  let owner: User;
  let admin: User;
  let member: User;
  let outsider: User;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    owner = await makeUser(t);
    admin = await makeUser(t);
    member = await makeUser(t);
    outsider = await makeUser(t);
  });
  afterEach(() => t.close());

  // A workspace of the owner, with the admin and the member in it.
  async function team(): Promise<string> {
    const id = await createWorkspace(t, owner, "Team");
    await addMember(t, owner, id, admin, "admin");
    await addMember(t, owner, id, member, "member");
    return id;
  }

  const roles = async (id: string) => {
    const res = await api(t, owner, "GET", `/v1/workspaces/${id}/members`);
    expect(res.statusCode).toBe(200);
    return new Map(
      res.json<MemberList>().members.map((m) => [m.account_id, m.role]),
    );
  };

  describe("create, read, rename, delete", () => {
    it("creates a workspace with an owner membership", async () => {
      const id = await createWorkspace(t, owner, "  Mine  ", "client");
      const got = await api(t, owner, "GET", `/v1/workspaces/${id}`);
      expect(got.statusCode).toBe(200);
      expect(got.json()).toEqual({
        id,
        name: "Mine",
        kind: "client",
        status: "active",
        role: "owner",
      });
      const list = await api(t, owner, "GET", "/v1/workspaces");
      expect(list.json<{ workspaces: { id: string }[] }>().workspaces).toEqual([
        expect.objectContaining({ id, role: "owner" }),
      ]);
      expect([...(await roles(id))]).toEqual([[owner.accountId, "owner"]]);
      const limits = await t.pool.query(
        "SELECT * FROM workspace_limits WHERE workspace_id = $1",
        [id],
      );
      expect(limits.rows[0]).toMatchObject({
        max_topics: 3,
        max_members: 5,
        max_keys: 5,
        msgs_per_day: 1000,
        msgs_per_min: 60,
        max_body_bytes: 2048,
        retention_days: 30,
      });
    });

    it("refuses bad names and kinds, and never creates dgl_internal", async () => {
      for (const payload of [
        { name: "", kind: "team" },
        { name: "   ", kind: "team" },
        { name: "x".repeat(61), kind: "team" },
        { name: "bad\nname", kind: "team" },
        { name: "ok", kind: "dgl_internal" },
        { name: "ok", kind: "other" },
        { name: 5, kind: "team" },
        { kind: "team" },
      ]) {
        const res = await api(t, owner, "POST", "/v1/workspaces", payload);
        expect(res.statusCode, JSON.stringify(payload)).toBe(400);
      }
      const none = await t.pool.query("SELECT 1 FROM workspaces");
      expect(none.rowCount).toBe(0);
    });

    it("needs a session", async () => {
      const res = await t.app.inject({ method: "GET", url: "/v1/workspaces" });
      expect(res.statusCode).toBe(401);
    });

    it("lets the owner and admin rename, and not the member", async () => {
      const id = await team();
      const byAdmin = await api(t, admin, "PATCH", `/v1/workspaces/${id}`, {
        name: "Renamed",
      });
      expect(byAdmin.statusCode).toBe(200);
      const bad = await api(t, owner, "PATCH", `/v1/workspaces/${id}`, {
        name: "",
      });
      expect(bad.statusCode).toBe(400);
      const byMember = await api(t, member, "PATCH", `/v1/workspaces/${id}`, {
        name: "Nope",
      });
      expect(byMember.statusCode).toBe(403);
      const got = await api(t, member, "GET", `/v1/workspaces/${id}`);
      expect(got.json<{ name: string }>().name).toBe("Renamed");
    });

    it("lets only the owner delete, and removes everything in it", async () => {
      const id = await team();
      expect(
        (await api(t, admin, "DELETE", `/v1/workspaces/${id}`)).statusCode,
      ).toBe(403);
      expect(
        (await api(t, owner, "DELETE", `/v1/workspaces/${id}`)).statusCode,
      ).toBe(204);
      for (const who of [owner, admin, member]) {
        const got = await api(t, who, "GET", `/v1/workspaces/${id}`);
        expect(got.statusCode).toBe(404);
      }
      const rows = await t.pool.query(
        "SELECT 1 FROM workspaces WHERE id = $1",
        [id],
      );
      expect(rows.rowCount).toBe(0);
    });

    it("answers 404 for a path id that is not a uuid", async () => {
      const res = await api(t, owner, "GET", "/v1/workspaces/not-a-uuid");
      expect(res.statusCode).toBe(404);
    });
  });

  describe("cross-workspace deny", () => {
    it("gives a member of another workspace 404 on every endpoint", async () => {
      const target = await team();
      const mine = await createWorkspace(t, outsider, "Mine");
      // Positive control: the outsider is a real member of its own workspace.
      expect(
        (await api(t, outsider, "GET", `/v1/workspaces/${mine}`)).statusCode,
      ).toBe(200);
      const base = `/v1/workspaces/${target}`;
      const calls: [Parameters<typeof api>[2], string, object?][] = [
        ["GET", base],
        ["PATCH", base, { name: "Hijack" }],
        ["DELETE", base],
        ["GET", `${base}/members`],
        ["PATCH", `${base}/members/${member.accountId}`, { role: "admin" }],
        ["DELETE", `${base}/members/${member.accountId}`],
        ["DELETE", `${base}/members/${outsider.accountId}`],
        ["POST", `${base}/transfer`, { accountId: outsider.accountId }],
        [
          "POST",
          `${base}/invitations`,
          { email: outsider.email, role: "admin" },
        ],
        ["DELETE", `${base}/invitations/${randomUUID()}`],
      ];
      for (const [method, url, payload] of calls) {
        const res = await api(t, outsider, method, url, payload);
        expect(res.statusCode, `${method} ${url}`).toBe(404);
      }
      // Nothing changed.
      const got = await api(t, owner, "GET", base);
      expect(got.json()).toMatchObject({ name: "Team", role: "owner" });
      expect((await roles(target)).size).toBe(3);
    });

    it("does not list another account's workspaces", async () => {
      await team();
      const list = await api(t, outsider, "GET", "/v1/workspaces");
      expect(list.json<{ workspaces: unknown[] }>().workspaces).toEqual([]);
    });
  });

  describe("role deny", () => {
    it("gives a member 403 on invite, remove, role change, rename, transfer and delete", async () => {
      const id = await team();
      const base = `/v1/workspaces/${id}`;
      const calls: [Parameters<typeof api>[2], string, object?][] = [
        [
          "POST",
          `${base}/invitations`,
          { email: outsider.email, role: "member" },
        ],
        ["DELETE", `${base}/invitations/${randomUUID()}`],
        ["DELETE", `${base}/members/${admin.accountId}`],
        ["PATCH", `${base}/members/${admin.accountId}`, { role: "member" }],
        ["PATCH", base, { name: "Nope" }],
        ["POST", `${base}/transfer`, { accountId: member.accountId }],
        ["DELETE", base],
      ];
      for (const [method, url, payload] of calls) {
        const res = await api(t, member, method, url, payload);
        expect(res.statusCode, `${method} ${url}`).toBe(403);
      }
      // A member may still read.
      expect((await api(t, member, "GET", base)).statusCode).toBe(200);
      expect((await api(t, member, "GET", `${base}/members`)).statusCode).toBe(
        200,
      );
      expect((await roles(id)).size).toBe(3);
    });

    it("gives an admin 403 on transfer, delete, and on the owner", async () => {
      const id = await team();
      const base = `/v1/workspaces/${id}`;
      const calls: [Parameters<typeof api>[2], string, object?][] = [
        ["POST", `${base}/transfer`, { accountId: admin.accountId }],
        ["DELETE", base],
        ["DELETE", `${base}/members/${owner.accountId}`],
        ["PATCH", `${base}/members/${owner.accountId}`, { role: "member" }],
        ["PATCH", `${base}/members/${owner.accountId}`, { role: "admin" }],
      ];
      for (const [method, url, payload] of calls) {
        const res = await api(t, admin, method, url, payload);
        expect(res.statusCode, `${method} ${url}`).toBe(403);
      }
      expect((await roles(id)).get(owner.accountId)).toBe("owner");
    });

    it("lets an admin invite, and remove or change a member", async () => {
      const id = await team();
      const base = `/v1/workspaces/${id}`;
      const changed = await api(
        t,
        admin,
        "PATCH",
        `${base}/members/${member.accountId}`,
        { role: "admin" },
      );
      expect(changed.statusCode).toBe(200);
      expect((await roles(id)).get(member.accountId)).toBe("admin");
      const removed = await api(
        t,
        admin,
        "DELETE",
        `${base}/members/${member.accountId}`,
      );
      expect(removed.statusCode).toBe(204);
      expect((await roles(id)).has(member.accountId)).toBe(false);
      expect((await api(t, member, "GET", base)).statusCode).toBe(404);
    });

    it("never makes anyone an owner through a role change", async () => {
      const id = await team();
      const res = await api(
        t,
        owner,
        "PATCH",
        `/v1/workspaces/${id}/members/${member.accountId}`,
        { role: "owner" },
      );
      expect(res.statusCode).toBe(400);
      expect((await roles(id)).get(member.accountId)).toBe("member");
    });

    it("does not let the owner leave or remove themself", async () => {
      const id = await team();
      const res = await api(
        t,
        owner,
        "DELETE",
        `/v1/workspaces/${id}/members/${owner.accountId}`,
      );
      expect(res.statusCode).toBe(403);
      const demote = await api(
        t,
        owner,
        "PATCH",
        `/v1/workspaces/${id}/members/${owner.accountId}`,
        { role: "member" },
      );
      expect(demote.statusCode).toBe(403);
      expect((await roles(id)).get(owner.accountId)).toBe("owner");
    });

    it("lets a member and an admin leave", async () => {
      const id = await team();
      for (const who of [member, admin]) {
        const res = await api(
          t,
          who,
          "DELETE",
          `/v1/workspaces/${id}/members/${who.accountId}`,
        );
        expect(res.statusCode).toBe(204);
        expect(
          (await api(t, who, "GET", `/v1/workspaces/${id}`)).statusCode,
        ).toBe(404);
      }
      expect([...(await roles(id)).keys()]).toEqual([owner.accountId]);
    });

    it("gives a member 403 when removing an id that is not their own", async () => {
      const id = await team();
      const res = await api(
        t,
        member,
        "DELETE",
        `/v1/workspaces/${id}/members/${randomUUID()}`,
      );
      expect(res.statusCode).toBe(403);
    });
  });

  describe("transfer", () => {
    it("moves ownership to a member and demotes the old owner", async () => {
      const id = await team();
      const res = await api(t, owner, "POST", `/v1/workspaces/${id}/transfer`, {
        accountId: admin.accountId,
      });
      expect(res.statusCode).toBe(200);
      const asAdmin = await api(
        t,
        admin,
        "GET",
        `/v1/workspaces/${id}/members`,
      );
      const map = new Map(
        asAdmin.json<MemberList>().members.map((m) => [m.account_id, m.role]),
      );
      expect(map.get(admin.accountId)).toBe("owner");
      expect(map.get(owner.accountId)).toBe("admin");
      const row = await t.pool.query<{ owner_id: string }>(
        "SELECT owner_id FROM workspaces WHERE id = $1",
        [id],
      );
      expect(row.rows[0]?.owner_id).toBe(admin.accountId);
      // The old owner can no longer delete.
      expect(
        (await api(t, owner, "DELETE", `/v1/workspaces/${id}`)).statusCode,
      ).toBe(403);
      expect(
        (await api(t, admin, "DELETE", `/v1/workspaces/${id}`)).statusCode,
      ).toBe(204);
    });

    it("needs a member as the target, and not the owner", async () => {
      const id = await team();
      const url = `/v1/workspaces/${id}/transfer`;
      const stranger = await api(t, owner, "POST", url, {
        accountId: outsider.accountId,
      });
      expect(stranger.statusCode).toBe(404);
      const self = await api(t, owner, "POST", url, {
        accountId: owner.accountId,
      });
      expect(self.statusCode).toBe(400);
      const bad = await api(t, owner, "POST", url, { accountId: "nope" });
      expect(bad.statusCode).toBe(400);
      expect((await roles(id)).get(owner.accountId)).toBe("owner");
    });

    it("refuses with 409 when the target already owns 3 workspaces", async () => {
      const id = await team();
      for (let i = 0; i < 3; i += 1) {
        await createWorkspace(t, admin, `Admin's ${i}`);
      }
      const res = await api(t, owner, "POST", `/v1/workspaces/${id}/transfer`, {
        accountId: admin.accountId,
      });
      expect(res.statusCode).toBe(409);
      const roleMap = await roles(id);
      expect(roleMap.get(owner.accountId)).toBe("owner");
      expect(roleMap.get(admin.accountId)).toBe("admin");
      // A target with room still works.
      const ok = await api(t, owner, "POST", `/v1/workspaces/${id}/transfer`, {
        accountId: member.accountId,
      });
      expect(ok.statusCode).toBe(200);
    });
  });

  describe("T-WS-CAPS", () => {
    it("refuses a 4th workspace for an account with 409", async () => {
      for (let i = 0; i < 3; i += 1) {
        await createWorkspace(t, owner, `W${i}`);
      }
      const res = await api(t, owner, "POST", "/v1/workspaces", {
        name: "W3",
        kind: "team",
      });
      expect(res.statusCode).toBe(409);
      const count = await t.pool.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM workspaces WHERE owner_id = $1",
        [owner.accountId],
      );
      expect(count.rows[0]?.n).toBe(3);
      // Another account is not affected.
      await createWorkspace(t, outsider, "Other");
    });

    it("counts workspaces that the account owns, not ones it joined", async () => {
      const id = await team();
      for (let i = 0; i < 3; i += 1) {
        await createWorkspace(t, admin, `Mine${i}`);
      }
      expect((await roles(id)).has(admin.accountId)).toBe(true);
    });

    it("refuses with 503 when the global ceiling is reached", async () => {
      const owner_ = ownerPool();
      try {
        const existing = await t.pool.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM workspaces",
        );
        const n = existing.rows[0]?.n ?? 0;
        await createWorkspace(t, owner, "First");
        await owner_.query(
          "UPDATE service_limits SET max_workspaces_total = $1",
          [n + 1],
        );
        const res = await api(t, outsider, "POST", "/v1/workspaces", {
          name: "Over",
          kind: "team",
        });
        expect(res.statusCode).toBe(503);
        await owner_.query(
          "UPDATE service_limits SET max_workspaces_total = $1",
          [n + 2],
        );
        await createWorkspace(t, outsider, "Fits");
        expect(
          (
            await api(t, owner, "POST", "/v1/workspaces", {
              name: "Over again",
              kind: "team",
            })
          ).statusCode,
        ).toBe(503);
      } finally {
        await owner_.query(
          "UPDATE service_limits SET max_workspaces_total = 2000",
        );
        await owner_.end();
      }
    });
  });

  describe("T-AUDIT", () => {
    const actions = async (workspaceId: string) => {
      const res = await t.pool.query<{ action: string; n: number }>(
        `SELECT action, count(*)::int AS n FROM audit_log
          WHERE workspace_id = $1 GROUP BY action`,
        [workspaceId],
      );
      return Object.fromEntries(res.rows.map((r) => [r.action, r.n]));
    };

    it("writes exactly one row for each action", async () => {
      const id = await createWorkspace(t, owner, "Audited");
      expect(await actions(id)).toEqual({ "workspace.create": 1 });

      await api(t, owner, "PATCH", `/v1/workspaces/${id}`, { name: "Renamed" });
      await addMember(t, owner, id, admin, "admin"); // invite.create + invite.accept
      await addMember(t, owner, id, member, "member"); // again
      await api(
        t,
        owner,
        "PATCH",
        `/v1/workspaces/${id}/members/${member.accountId}`,
        {
          role: "admin",
        },
      );
      const invited = await api(
        t,
        owner,
        "POST",
        `/v1/workspaces/${id}/invitations`,
        {
          email: outsider.email,
          role: "member",
        },
      );
      const inviteId = invited.json<{ id: string }>().id;
      await api(
        t,
        owner,
        "DELETE",
        `/v1/workspaces/${id}/invitations/${inviteId}`,
      );
      await api(
        t,
        owner,
        "DELETE",
        `/v1/workspaces/${id}/members/${member.accountId}`,
      );
      await api(t, owner, "POST", `/v1/workspaces/${id}/transfer`, {
        accountId: admin.accountId,
      });
      await api(t, admin, "DELETE", `/v1/workspaces/${id}`);

      expect(await actions(id)).toEqual({
        "workspace.create": 1,
        "workspace.rename": 1,
        "invite.create": 3,
        "invite.accept": 2,
        "invite.cancel": 1,
        "member.role_change": 1,
        "member.remove": 1,
        "workspace.transfer": 1,
        "workspace.delete": 1,
      });
    });

    it("writes nothing for a refused action", async () => {
      const id = await team();
      const before = await actions(id);
      await api(t, member, "PATCH", `/v1/workspaces/${id}`, { name: "Nope" });
      await api(t, outsider, "DELETE", `/v1/workspaces/${id}`);
      await api(t, admin, "POST", `/v1/workspaces/${id}/transfer`, {
        accountId: admin.accountId,
      });
      expect(await actions(id)).toEqual(before);
    });

    it("cannot be changed or deleted by the app role, and holds no email", async () => {
      await createWorkspace(t, owner, "Audited");
      await expect(
        t.pool.query("UPDATE audit_log SET reason = 'x'"),
      ).rejects.toThrow(/permission denied/);
      await expect(t.pool.query("DELETE FROM audit_log")).rejects.toThrow(
        /permission denied/,
      );
      const rows = await t.pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_log
          WHERE target LIKE '%@%' OR reason LIKE '%@%'`,
      );
      expect(rows.rows[0]?.n).toBe(0);
    });
  });
});
