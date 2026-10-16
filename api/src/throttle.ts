import type { Db } from "./db.ts";

export const WINDOW_MS = 15 * 60 * 1000;
export const IP_LIMIT = 20;
// Login links sent per account in one window.
export const LOGIN_LINK_LIMIT = 3;
const MAX_ROWS = 1000;

// Window maths. Given failure times (ms), returns 0 if another attempt is
// allowed, or the seconds until it will be (the Retry-After value). Blocked
// once `limit` failures lie inside the window; unblocked when enough of the
// oldest ones age out.
export function retryAfterSeconds(
  failureTimes: number[],
  nowMs: number,
  limit: number,
  windowMs: number = WINDOW_MS,
): number {
  const inWindow = failureTimes
    .filter((t) => t > nowMs - windowMs)
    .sort((a, b) => a - b);
  if (inWindow.length < limit) return 0;
  const oldestThatMatters = inWindow[inWindow.length - limit] as number;
  return Math.max(1, Math.ceil((oldestThatMatters + windowMs - nowMs) / 1000));
}

// Takes a transaction-scoped lock for one key (an IP or an account), so a
// parallel burst cannot pass a limit between the check and the record.
// Callers take the IP lock first and the account lock second.
export async function lockKey(
  db: Db,
  kind: "ip" | "account",
  value: string,
): Promise<void> {
  await db.query("SELECT pg_advisory_xact_lock(hashtext($1::text))", [
    `throttle:${kind}:${value}`,
  ]);
}

async function attemptTimes(db: Db, ip: string, now: Date): Promise<number[]> {
  const since = new Date(now.getTime() - WINDOW_MS);
  const result = await db.query<{ created_at: Date }>(
    `SELECT created_at FROM login_failures
      WHERE ip = $1 AND created_at > $2
      ORDER BY created_at ASC LIMIT ${MAX_ROWS}`,
    [ip, since],
  );
  return result.rows.map((row) => row.created_at.getTime());
}

// Returns 0 if the attempt may go ahead, else the Retry-After seconds. Limits
// are per IP only, so a 429 says nothing about any account. Call it after
// lockKey(db, "ip", ip), in the same transaction as recordAttempt.
export async function checkThrottle(
  db: Db,
  now: Date,
  ip: string,
): Promise<number> {
  return retryAfterSeconds(
    await attemptTimes(db, ip, now),
    now.getTime(),
    IP_LIMIT,
  );
}

// Records one login request or failed redeem against the IP. The account is
// never recorded.
export async function recordAttempt(
  db: Db,
  now: Date,
  ip: string,
): Promise<void> {
  await db.query(
    "INSERT INTO login_failures (account_id, ip, created_at) VALUES (NULL, $1, $2)",
    [ip, now],
  );
}
