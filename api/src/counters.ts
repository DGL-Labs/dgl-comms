import { randomInt } from "node:crypto";
import type { Pool } from "pg";
import { autocommit, first } from "./db.ts";

// Every counter below is one statement in its own transaction (autocommit), so
// a refusal or a debit is kept even if the request fails afterwards. A failed
// publish still counts (docs/KNOWN-GAPS.md).

export const CALLER_PER_MINUTE = 60;
const SHARDS = 16;

// Takes one token from a bucket that holds `perMinute` tokens and refills at
// that many a minute, measured from updated_at by the database clock, in the
// same statement. True if a token was taken. A first use fills the bucket. A
// refusal leaves the row alone, so the refill keeps counting.
export async function takeToken(
  pool: Pool,
  bucket: string,
  perMinute: number,
): Promise<boolean> {
  // A missing or zero limit fails closed.
  if (!Number.isFinite(perMinute) || perMinute < 1) return false;
  const taken = await autocommit<{ tokens: string }>(
    pool,
    `INSERT INTO rate_buckets (bucket, tokens, updated_at)
     VALUES ($1, $2::numeric - 1, now())
     ON CONFLICT (bucket) DO UPDATE
       SET tokens = least($2::numeric, rate_buckets.tokens
             + extract(epoch FROM now() - rate_buckets.updated_at)
               * $2::numeric / 60) - 1,
           updated_at = now()
     WHERE least($2::numeric, rate_buckets.tokens
             + extract(epoch FROM now() - rate_buckets.updated_at)
               * $2::numeric / 60) >= 1
     RETURNING tokens`,
    [bucket, perMinute],
  );
  return first(taken.rows) !== undefined;
}

// The caller bucket, first of all: ip:<address> for a key caller (every key
// attempt, good or bad), acct:<account id> for a session caller.
export function takeCallerToken(pool: Pool, bucket: string): Promise<boolean> {
  return takeToken(pool, bucket, CALLER_PER_MINUTE);
}

// The workspace's per-minute bucket.
export function takeWorkspaceToken(
  pool: Pool,
  workspaceId: string,
  perMinute: number,
): Promise<boolean> {
  return takeToken(pool, `ws:${workspaceId}`, perMinute);
}

// One message of the workspace's daily allowance (the day by the database
// clock). True if it was within the limit; the count only goes up while it is
// below the limit.
export async function takeDailyMessage(
  pool: Pool,
  workspaceId: string,
  limit: number,
): Promise<boolean> {
  // The insert path has no limit check of its own, so a limit below 1 fails
  // closed here.
  if (!Number.isFinite(limit) || limit < 1) return false;
  const taken = await autocommit<{ count: number }>(
    pool,
    `INSERT INTO workspace_usage_daily (workspace_id, day, count)
     VALUES ($1, current_date, 1)
     ON CONFLICT (workspace_id, day) DO UPDATE
       SET count = workspace_usage_daily.count + 1
     WHERE workspace_usage_daily.count < $2
     RETURNING count`,
    [workspaceId, limit],
  );
  return first(taken.rows) !== undefined;
}

// One message of the global daily ceiling, for a non-internal workspace. The
// count goes to a random shard of this minute, and only if today's total over
// all shards is below max_msgs_per_day_total. A missing service_limits row
// gives no row to insert, which is a refusal. Writers on different shards do
// not wait on each other, so the total can pass the ceiling by about the
// number of publishes in flight at once.
export async function takeGlobalMessage(pool: Pool): Promise<boolean> {
  const taken = await autocommit<{ count: number }>(
    pool,
    `WITH used AS (
       SELECT coalesce(sum(count), 0) AS n FROM global_usage_minute
        WHERE minute >= date_trunc('day', now())
     ), lim AS (
       SELECT max_msgs_per_day_total AS n FROM service_limits
     )
     INSERT INTO global_usage_minute (minute, shard, count)
     SELECT date_trunc('minute', now()), $1::smallint, 1
       FROM used, lim WHERE used.n < lim.n
     ON CONFLICT (minute, shard) DO UPDATE
       SET count = global_usage_minute.count + 1
     RETURNING count`,
    [randomInt(SHARDS)],
  );
  return first(taken.rows) !== undefined;
}
