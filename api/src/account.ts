import { writeAudit } from "./audit.ts";
import { loadContext } from "./db.ts";
import type { Db } from "./db.ts";

export type DeleteResult =
  // Deleted. The ids are the live sessions that the delete ends.
  | { kind: "deleted"; endedSessions: string[] }
  // The caller owns a workspace that has other members. Nothing was deleted.
  | { kind: "shared"; workspaces: { id: string; members: number }[] }
  // Every owned workspace is solely the caller's, and the caller has not
  // confirmed. Nothing was deleted.
  | { kind: "confirm"; workspaces: { id: string }[] };

// Deletes an account inside the caller's transaction. Sessions and magic links
// go by ON DELETE CASCADE.
//
// An account never deletes, or silently hands over, a workspace that holds
// other members' data (PC ruling). While the caller owns any workspace with
// other members, nothing is deleted. Solely-owned workspaces are deleted only
// with confirm. Ownership is never transferred here.
//
// The caller's context is set here as well, so this does not depend on the
// route having done it: the membership counts below need it.
export async function deleteAccount(
  tx: Db,
  accountId: string,
  options: { confirm?: boolean; now?: Date } = {},
): Promise<DeleteResult> {
  const now = options.now ?? new Date();
  const scope = await loadContext(tx, accountId);

  // Lock the owned workspaces, in id order. Accepting an invitation locks the
  // same row, so no member can join between the count and the delete.
  // The owner is authoritative here, so these join the context even if a
  // membership row were ever missing: the count must not under-report. They
  // join before the lock, because FOR UPDATE passes the UPDATE policy.
  const candidates = await tx.query<{ id: string }>(
    "SELECT id FROM workspaces WHERE owner_id = $1 ORDER BY id",
    [accountId],
  );
  await scope.addWorkspaces(candidates.rows.map((row) => row.id));
  const owned = await tx.query<{ id: string }>(
    "SELECT id FROM workspaces WHERE owner_id = $1 ORDER BY id FOR UPDATE",
    [accountId],
  );
  const ownedIds = owned.rows.map((row) => row.id);
  await scope.addWorkspaces(ownedIds);
  const counted = await tx.query<{
    workspace_id: string;
    members: number;
    others: number;
  }>(
    `SELECT workspace_id,
            count(*)::int AS members,
            (count(*) FILTER (WHERE account_id <> $2))::int AS others
       FROM members
      WHERE workspace_id = ANY ($1::uuid[])
      GROUP BY workspace_id`,
    [ownedIds, accountId],
  );
  const shared = counted.rows
    .filter((row) => row.others > 0)
    .map((row) => ({ id: row.workspace_id, members: row.members }));
  if (shared.length > 0) return { kind: "shared", workspaces: shared };
  if (ownedIds.length > 0 && options.confirm !== true) {
    return { kind: "confirm", workspaces: ownedIds.map((id) => ({ id })) };
  }

  const live = await tx.query<{ id: string }>(
    "SELECT id FROM sessions WHERE account_id = $1 AND revoked_at IS NULL",
    [accountId],
  );
  // login_failures has no foreign key (it also records unknown addresses), so
  // its rows for this account are removed here.
  await tx.query("DELETE FROM login_failures WHERE account_id = $1", [
    accountId,
  ]);

  // Solely-owned workspaces, with their members, invitations, limits and keys
  // (ON DELETE CASCADE).
  for (const id of ownedIds) {
    await tx.query("DELETE FROM workspaces WHERE id = $1", [id]);
    await writeAudit(tx, now, {
      actorAccountId: accountId,
      workspaceId: id,
      action: "workspace.delete",
      target: id,
      reason: "account_deleted",
    });
  }
  // Memberships in workspaces the caller only joined. Those workspaces and
  // the other members' data stay.
  await tx.query("DELETE FROM members WHERE account_id = $1", [accountId]);

  // ===== EXTENSION POINT =====
  // C-1d and C-1f add their own cascades here, in this transaction and
  // before the account row goes: rows of theirs that do not cascade from
  // accounts (messages, push tokens, device records, and so on).
  // ===== END EXTENSION POINT =====

  await writeAudit(tx, now, {
    actorAccountId: accountId,
    workspaceId: null,
    action: "account.delete",
    target: accountId,
  });
  await tx.query("DELETE FROM accounts WHERE id = $1", [accountId]);
  return { kind: "deleted", endedSessions: live.rows.map((row) => row.id) };
}
