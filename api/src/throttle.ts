import type { Db } from "./db.ts";

export const WINDOW_MS = 15 * 60 * 1000;
export const ACCOUNT_LIMIT = 5;
export const IP_LIMIT = 20;
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

async function failureTimes(
  db: Db,
  column: "account_id" | "ip",
  value: string,
  now: Date,
): Promise<number[]> {
  const since = new Date(now.getTime() - WINDOW_MS);
  const result = await db.query<{ created_at: Date }>(
    `SELECT created_at FROM login_failures
      WHERE ${column} = $1 AND created_at > $2
      ORDER BY created_at ASC LIMIT ${MAX_ROWS}`,
    [value, since],
  );
  return result.rows.map((row) => row.created_at.getTime());
}

// Returns 0 if the attempt may go ahead, else the Retry-After seconds.
export async function checkThrottle(
  db: Db,
  now: Date,
  accountId: string | null,
  ip: string,
): Promise<number> {
  const byIp = retryAfterSeconds(
    await failureTimes(db, "ip", ip, now),
    now.getTime(),
    IP_LIMIT,
  );
  const byAccount =
    accountId === null
      ? 0
      : retryAfterSeconds(
          await failureTimes(db, "account_id", accountId, now),
          now.getTime(),
          ACCOUNT_LIMIT,
        );
  return Math.max(byIp, byAccount);
}

export async function recordFailure(
  db: Db,
  now: Date,
  accountId: string | null,
  ip: string,
): Promise<void> {
  await db.query(
    "INSERT INTO login_failures (account_id, ip, created_at) VALUES ($1, $2, $3)",
    [accountId, ip, now],
  );
}
