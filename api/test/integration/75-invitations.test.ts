import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withContext } from "../../src/db.ts";
import { hashToken } from "../../src/tokens.ts";
import {
  addMember,
  api,
  createWorkspace,
  makeApp,
  makeUser,
  ownerPool,
  redeem,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp, User } from "./harness.ts";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

// T-INVITE-CAPS and the invitation flow.
describe("invitations", () => {
  let t: TestApp;
  let owner: User;
  let admin: User;
  let member: User;
  let invitee: User;
  let ws: string;

  beforeEach(async () => {
    t = await makeApp({ allowlistOn: false });
    owner = await makeUser(t);
    admin = await makeUser(t);
    member = await makeUser(t);
    invitee = await makeUser(t);
    ws = await createWorkspace(t, owner, "Team");
  });
  afterEach(() => t.close());

  const invite = (who: User, email: string, role = "member", id = ws) =>
    api(t, who, "POST", `/v1/workspaces/${id}/invitations`, { email, role });
  const accept = (who: User, token: string) =>
    api(t, who, "POST", "/v1/invitations/accept", { token });
  const tokenFor = (email: string): string => {
    const message = t.sender.lastTo(email);
    if (message === undefined || message.kind !== "invite") {
      throw new Error("no invite email");
    }
    return message.token;
  };
  const memberCount = async () => {
    const res = await api(t, owner, "GET", `/v1/workspaces/${ws}/members`);
    return res.json<{ members: unknown[] }>().members.length;
  };

  async function signUpLate(email: string, ip: string): Promise<User> {
    return { ...(await signupAndVerify(t, email, ip)), email };
  }

  // A new session for an existing account, through a login link.
  async function relogin(who: User, ip: string): Promise<User> {
    const sent = await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      remoteAddress: ip,
      payload: { email: who.email },
    });
    expect(sent.statusCode).toBe(202);
    const message = t.sender.lastTo(who.email);
    if (message === undefined) throw new Error("no login email");
    const res = await redeem(t, message.token, ip);
    expect(res.statusCode).toBe(200);
    const body = res.json<{ access_token: string; refresh_token: string }>();
    return {
      ...who,
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
    };
  }

  // The app cannot change limits, so tests that need room use the owner role.
  async function setMaxMembers(n: number): Promise<void> {
    const db = ownerPool();
    try {
      await db.query(
        "UPDATE workspace_limits SET max_members = $2 WHERE workspace_id = $1",
        [ws, n],
      );
    } finally {
      await db.end();
    }
  }

  it("refuses with 409 to invite a member, using no email, cap slot or member slot", async () => {
    await addMember(t, owner, ws, member);
    const tokenBefore = tokenFor(member.email);
    const slots = async () =>
      (
        await t.pool.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM audit_log
            WHERE workspace_id = $1 AND action = 'invite.create'`,
          [ws],
        )
      ).rows[0]?.n;
    const slotsBefore = await slots();
    const res = await invite(owner, member.email, "admin");
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: "already_member" });
    expect(tokenFor(member.email)).toBe(tokenBefore);
    expect(await slots()).toBe(slotsBefore);
    expect(await memberCount()).toBe(2);
    const pending = await withContext(
      t.pool,
      { accountId: owner.accountId },
      (tx) =>
        tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM invitations
            WHERE workspace_id = $1 AND used_at IS NULL`,
          [ws],
        ),
    );
    expect(pending.rows[0]?.n).toBe(0);
  });

  it("sends the token by email only, in fixed text", async () => {
    const res = await invite(owner, invitee.email, "admin");
    expect(res.statusCode).toBe(201);
    expect(JSON.stringify(res.json())).not.toContain(tokenFor(invitee.email));
    const message = t.sender.lastTo(invitee.email);
    expect(message?.kind).toBe("invite");
    expect(message?.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Only the SHA-256 of the token is stored, and the invitation lasts 7 days.
    const row = await withContext(
      t.pool,
      { accountId: owner.accountId },
      (tx) =>
        tx.query<{ token_hash: Buffer; role: string; span: number }>(
          `SELECT token_hash, role,
                extract(epoch FROM expires_at - created_at)::int AS span
           FROM invitations WHERE workspace_id = $1`,
          [ws],
        ),
    );
    expect(row.rows).toHaveLength(1);
    expect(
      row.rows[0]?.token_hash.equals(hashToken(tokenFor(invitee.email))),
    ).toBe(true);
    expect(row.rows[0]?.role).toBe("admin");
    expect(row.rows[0]?.span).toBe(WEEK_MS / 1000);
  });

  it("lets the invitee join with the invited role, once", async () => {
    await invite(owner, invitee.email, "admin");
    const token = tokenFor(invitee.email);
    const joined = await accept(invitee, token);
    expect(joined.statusCode).toBe(200);
    expect(joined.json()).toEqual({ workspace_id: ws });
    const got = await api(t, invitee, "GET", `/v1/workspaces/${ws}`);
    expect(got.json()).toMatchObject({ role: "admin" });
    // Reused.
    const again = await accept(invitee, token);
    expect(again.statusCode).toBe(404);
    expect(await memberCount()).toBe(2);
  });

  it("refuses a token for another email, and keeps it usable by the right one", async () => {
    await invite(owner, invitee.email);
    const token = tokenFor(invitee.email);
    const wrong = await accept(member, token);
    expect(wrong.statusCode).toBe(404);
    expect(wrong.json()).toEqual({ error: "not_found" });
    expect(
      (await api(t, member, "GET", `/v1/workspaces/${ws}`)).statusCode,
    ).toBe(404);
    expect((await accept(invitee, token)).statusCode).toBe(200);
  });

  it("refuses unknown tokens and bad bodies", async () => {
    expect((await accept(invitee, "nonsense")).statusCode).toBe(404);
    const noBody = await api(t, invitee, "POST", "/v1/invitations/accept", {});
    expect(noBody.statusCode).toBe(400);
    const noSession = await t.app.inject({
      method: "POST",
      url: "/v1/invitations/accept",
      payload: { token: "x" },
    });
    expect(noSession.statusCode).toBe(401);
  });

  it("refuses an expired invitation", async () => {
    const email = uniqueEmail();
    expect((await invite(owner, email)).statusCode).toBe(201);
    const token = tokenFor(email);
    t.clock.advance(WEEK_MS + 1000);
    // Sessions are short, so the invitee signs up only now.
    const late = await signUpLate(email, "198.51.100.250");
    const res = await accept(late, token);
    expect(res.statusCode).toBe(404);
  });

  it("accepts an invitation just before it expires", async () => {
    const email = uniqueEmail();
    await invite(owner, email);
    const token = tokenFor(email);
    t.clock.advance(WEEK_MS - 60_000);
    const late = await signUpLate(email, "198.51.100.251");
    expect((await accept(late, token)).statusCode).toBe(200);
  });

  it("refuses a cancelled invitation", async () => {
    const created = await invite(owner, invitee.email);
    const token = tokenFor(invitee.email);
    const id = created.json<{ id: string }>().id;
    const gone = await api(
      t,
      owner,
      "DELETE",
      `/v1/workspaces/${ws}/invitations/${id}`,
    );
    expect(gone.statusCode).toBe(204);
    expect((await accept(invitee, token)).statusCode).toBe(404);
    const twice = await api(
      t,
      owner,
      "DELETE",
      `/v1/workspaces/${ws}/invitations/${id}`,
    );
    expect(twice.statusCode).toBe(404);
  });

  it("cannot cancel an invitation of another workspace", async () => {
    const other = await createWorkspace(t, owner, "Other");
    const created = await invite(owner, invitee.email, "member", other);
    const id = created.json<{ id: string }>().id;
    const res = await api(
      t,
      owner,
      "DELETE",
      `/v1/workspaces/${ws}/invitations/${id}`,
    );
    expect(res.statusCode).toBe(404);
    expect((await accept(invitee, tokenFor(invitee.email))).statusCode).toBe(
      200,
    );
  });

  it("a token for one workspace joins only that workspace", async () => {
    const mine = await createWorkspace(t, member, "Member's own");
    await invite(owner, invitee.email);
    // The owner of another workspace cannot use the token.
    const stolen = await accept(member, tokenFor(invitee.email));
    expect(stolen.statusCode).toBe(404);
    const res = await accept(invitee, tokenFor(invitee.email));
    expect(res.json()).toEqual({ workspace_id: ws });
    expect(
      (await api(t, invitee, "GET", `/v1/workspaces/${mine}`)).statusCode,
    ).toBe(404);
  });

  it("refuses an invitation for the owner role, a bad email, and a duplicate", async () => {
    expect((await invite(owner, invitee.email, "owner")).statusCode).toBe(400);
    expect((await invite(owner, "not-an-email")).statusCode).toBe(400);
    expect((await invite(owner, invitee.email)).statusCode).toBe(201);
    expect((await invite(owner, invitee.email.toUpperCase())).statusCode).toBe(
      409,
    );
  });

  it("refuses to invite someone who is already a member, at accept", async () => {
    await addMember(t, owner, ws, member);
    await invite(owner, member.email);
    const res = await accept(member, tokenFor(member.email));
    expect(res.statusCode).toBe(409);
  });

  describe("T-INVITE-CAPS", () => {
    it("refuses the 21st invitation in a day for an account", async () => {
      await setMaxMembers(1000);
      for (let i = 0; i < 20; i += 1) {
        const res = await invite(owner, uniqueEmail());
        expect(res.statusCode, `invite ${i + 1}`).toBe(201);
      }
      const over = await invite(owner, uniqueEmail());
      expect(over.statusCode).toBe(429);
      // Cancelling does not give the slot back.
      const rows = await withContext(
        t.pool,
        { accountId: owner.accountId },
        (tx) =>
          tx.query<{ id: string }>(
            "SELECT id FROM invitations WHERE workspace_id = $1",
            [ws],
          ),
      );
      const first = rows.rows[0]?.id;
      await api(
        t,
        owner,
        "DELETE",
        `/v1/workspaces/${ws}/invitations/${first}`,
      );
      expect((await invite(owner, uniqueEmail())).statusCode).toBe(429);
      // A day later it works again.
      t.clock.advance(24 * 60 * 60 * 1000 + 1000);
      const fresh = await relogin(owner, "198.51.100.252");
      const later = await api(
        t,
        fresh,
        "POST",
        `/v1/workspaces/${ws}/invitations`,
        {
          email: uniqueEmail(),
          role: "member",
        },
      );
      expect(later.statusCode).toBe(201);
    });

    it("refuses the 51st invitation in a day for a workspace", async () => {
      await setMaxMembers(1000);
      await addMember(t, owner, ws, admin, "admin");
      await addMember(t, owner, ws, member, "admin");
      // addMember made 2 invitations, both by the owner. The owner makes 18
      // more (20 in all), the admin 20 and the member 10: 50 in all.
      const plan: [User, number][] = [
        [owner, 18],
        [admin, 20],
        [member, 10],
      ];
      for (const [who, n] of plan) {
        for (let i = 0; i < n; i += 1) {
          const res = await invite(who, uniqueEmail());
          expect(res.statusCode).toBe(201);
        }
      }
      const over = await invite(member, uniqueEmail());
      expect(over.statusCode).toBe(429);
      const count = await t.pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_log
          WHERE workspace_id = $1 AND action = 'invite.create'`,
        [ws],
      );
      expect(count.rows[0]?.n).toBe(50);
    });

    it("counts pending invitations towards max_members", async () => {
      // The owner is 1 of 5 members.
      const emails = [
        uniqueEmail(),
        uniqueEmail(),
        uniqueEmail(),
        uniqueEmail(),
      ];
      for (const email of emails) {
        expect((await invite(owner, email)).statusCode).toBe(201);
      }
      const full = await invite(owner, uniqueEmail());
      expect(full.statusCode).toBe(409);
      expect(full.json()).toEqual({ error: "member_limit" });
    });

    it("gives the slot back when a pending invitation is cancelled", async () => {
      for (let i = 0; i < 3; i += 1) await invite(owner, uniqueEmail());
      const last = await invite(owner, uniqueEmail());
      expect(last.statusCode).toBe(201);
      expect((await invite(owner, uniqueEmail())).statusCode).toBe(409);
      const id = last.json<{ id: string }>().id;
      await api(t, owner, "DELETE", `/v1/workspaces/${ws}/invitations/${id}`);
      expect((await invite(owner, uniqueEmail())).statusCode).toBe(201);
    });

    it("refuses to accept into a full workspace", async () => {
      await setMaxMembers(2);
      expect((await invite(owner, invitee.email)).statusCode).toBe(201);
      // 1 member + 1 pending = 2: full for a second invitation.
      expect((await invite(owner, member.email)).statusCode).toBe(409);
      // The limit drops after the invitation was made.
      await setMaxMembers(1);
      const res = await accept(invitee, tokenFor(invitee.email));
      expect(res.statusCode).toBe(409);
      expect(res.json()).toEqual({ error: "member_limit" });
      expect(await memberCount()).toBe(1);
    });
  });
});
