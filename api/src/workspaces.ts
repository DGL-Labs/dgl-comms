import type { FastifyReply, FastifyRequest } from "fastify";
import type { Ctx } from "./context.ts";
import { first } from "./db.ts";
import type { Db } from "./db.ts";
import { can, isRole } from "./permissions.ts";
import type { Action, Role } from "./permissions.ts";

export type Decision =
  | { kind: "ok"; role: Role }
  | { kind: "not_found" }
  | { kind: "forbidden" };

// The caller's role in a workspace, or null. Row-level security only shows
// memberships of the caller's own workspaces, so another workspace gives null.
export async function memberRole(
  tx: Db,
  workspaceId: string,
  accountId: string,
): Promise<Role | null> {
  const found = await tx.query<{ role: string }>(
    "SELECT role FROM members WHERE workspace_id = $1 AND account_id = $2",
    [workspaceId, accountId],
  );
  const role = first(found.rows)?.role;
  return isRole(role) ? role : null;
}

async function decide(
  tx: Db,
  accountId: string,
  workspaceId: string,
  action: Action,
): Promise<Decision> {
  const role = await memberRole(tx, workspaceId, accountId);
  // Not a member of this workspace: 404, so ids do not leak.
  if (role === null) return { kind: "not_found" };
  // A member without the permission: 403.
  if (!can(role, action)) return { kind: "forbidden" };
  return { kind: "ok", role };
}

// Every workspace route calls this first. Any action other than a read also
// locks the workspace row and decides again, so changes to one workspace run
// one after another and a role change cannot be raced.
export async function authorize(
  ctx: Ctx,
  tx: Db,
  accountId: string,
  workspaceId: string,
  action: Action,
): Promise<Decision> {
  // Test hook only (AppDeps.testHooks). It is never set from config.
  if (ctx.skipPermissionChecks) return { kind: "ok", role: "owner" };
  const decision = await decide(tx, accountId, workspaceId, action);
  if (decision.kind !== "ok" || action === "workspace.read") return decision;
  await tx.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [
    workspaceId,
  ]);
  return decide(tx, accountId, workspaceId, action);
}

export function badRequest(request: FastifyRequest, reply: FastifyReply) {
  request.reason = "bad_request";
  return reply.code(400).send({ error: "bad_request" });
}

export function notFound(request: FastifyRequest, reply: FastifyReply) {
  request.reason = "not_found";
  return reply.code(404).send({ error: "not_found" });
}

export function forbidden(
  request: FastifyRequest,
  reply: FastifyReply,
  reason = "forbidden",
) {
  request.reason = reason;
  return reply.code(403).send({ error: "forbidden" });
}

// Sends the reply for a denied decision.
export function deny(
  request: FastifyRequest,
  reply: FastifyReply,
  decision: Exclude<Decision, { kind: "ok" }>,
) {
  return decision.kind === "not_found"
    ? notFound(request, reply)
    : forbidden(request, reply);
}
