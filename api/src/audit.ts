import type { Db } from "./db.ts";

export type AuditAction =
  | "workspace.create"
  | "workspace.rename"
  | "workspace.delete"
  | "workspace.transfer"
  | "member.role_change"
  | "member.remove"
  | "invite.create"
  | "invite.cancel"
  | "invite.accept"
  | "account.delete";

export interface AuditEntry {
  actorAccountId: string | null;
  workspaceId: string | null;
  action: AuditAction;
  // An id only, never an email.
  target?: string | null;
  // A fixed word, never user text.
  reason?: string | null;
}

// The audit log is append-only by grants: pingzo_app has INSERT and SELECT.
export async function writeAudit(
  db: Db,
  at: Date,
  entry: AuditEntry,
): Promise<void> {
  await db.query(
    `INSERT INTO audit_log (at, actor_account_id, workspace_id, action, target, reason)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      at,
      entry.actorAccountId,
      entry.workspaceId,
      entry.action,
      entry.target ?? null,
      entry.reason ?? null,
    ],
  );
}
