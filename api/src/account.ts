import type { Db } from "./db.ts";

// Deletes an account inside the caller's transaction. Sessions and magic links
// go by ON DELETE CASCADE. Returns the ids of the live sessions that the delete
// ends, so the caller can run the onSessionRevoked hook after the commit.
export async function deleteAccount(
  tx: Db,
  accountId: string,
): Promise<string[]> {
  const live = await tx.query<{ id: string }>(
    "SELECT id FROM sessions WHERE account_id = $1 AND revoked_at IS NULL",
    [accountId],
  );
  // login_failures has no foreign key (it also records unknown addresses), so
  // its rows for this account are removed here.
  await tx.query("DELETE FROM login_failures WHERE account_id = $1", [
    accountId,
  ]);

  // ===== EXTENSION POINT =====
  // C-1c, C-1d and C-1f add their own cascades here, in this transaction and
  // before the account row goes: rows of theirs that do not cascade from
  // accounts (messages, push tokens, device records, and so on).
  // ===== END EXTENSION POINT =====

  await tx.query("DELETE FROM accounts WHERE id = $1", [accountId]);
  return live.rows.map((row) => row.id);
}
