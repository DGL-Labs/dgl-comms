import type { Db } from "./db.ts";
import type { EmailKind } from "./email.ts";
import { hashToken, newToken } from "./tokens.ts";

export const MAGIC_LINK_TTL_MS = 15 * 60 * 1000;

// Stores only the SHA-256 of the token and returns the token for the email.
export async function createMagicLink(
  db: Db,
  accountId: string,
  purpose: EmailKind,
  now: Date,
): Promise<string> {
  const token = newToken();
  await db.query(
    `INSERT INTO magic_links (account_id, token_hash, purpose, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      accountId,
      hashToken(token),
      purpose,
      new Date(now.getTime() + MAGIC_LINK_TTL_MS),
      now,
    ],
  );
  return token;
}
