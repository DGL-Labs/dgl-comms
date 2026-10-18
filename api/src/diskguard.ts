import { readFile } from "node:fs/promises";
import type { Db } from "./db.ts";
import { pgCode } from "./db.ts";
import { isRecord } from "./input.ts";

// Disk guard, stage (a): the logic only. Its process arrives at C-1f. It runs
// as pingzo_maintainer, which can read and change the two pause flags, add
// alerts and audit rows, and touch no tenant table.
//
// Pass a pool or any connection in autocommit mode: each statement here stands
// alone, and the missing-status alert relies on a unique-violation error that
// would abort an open transaction.

export interface DiskReading {
  usedPercent: number;
}

export type ServiceFlag = "signup_paused" | "publish_paused_non_internal";

export const SIGNUP_PAUSE_PERCENT = 80;
export const PUBLISH_PAUSE_PERCENT = 90;

// A host status file is JSON: {"used_percent": 83.5}. Unset, missing,
// unreadable or malformed all give null, which checkDisk turns into one alert.
export async function readDiskStatus(
  path: string | null,
): Promise<DiskReading | null> {
  if (path === null) return null;
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    const used = isRecord(parsed) ? parsed.used_percent : undefined;
    if (
      typeof used !== "number" ||
      !Number.isFinite(used) ||
      used < 0 ||
      used > 100
    ) {
      return null;
    }
    return { usedPercent: used };
  } catch {
    return null;
  }
}

// The flag is set, and its alert written, in one statement: only the statement
// that really flips the flag writes the alert, so a repeat check, even a
// concurrent one, writes nothing.
const SIGNUP_PAUSE_SQL = `WITH changed AS (
  UPDATE service_limits SET signup_paused = true
   WHERE id AND NOT signup_paused
  RETURNING 1
)
INSERT INTO service_alerts (kind, level, detail)
SELECT 'disk_80', 'warning', $1::text FROM changed
RETURNING id`;

const PUBLISH_PAUSE_SQL = `WITH changed AS (
  UPDATE service_limits SET publish_paused_non_internal = true
   WHERE id AND NOT publish_paused_non_internal
  RETURNING 1
)
INSERT INTO service_alerts (kind, level, detail)
SELECT 'disk_90', 'critical', $1::text FROM changed
RETURNING id`;

// Returns the kinds of the alerts it raised. It never clears a flag.
export async function checkDisk(
  db: Db,
  reading: DiskReading | null,
): Promise<string[]> {
  const raised: string[] = [];
  if (reading === null) {
    try {
      await db.query(
        `INSERT INTO service_alerts (kind, level, detail)
         VALUES ('disk_status_missing', 'warning', '0')`,
      );
      raised.push("disk_status_missing");
    } catch (error) {
      // Already raised and not yet delivered: once is enough.
      if (pgCode(error) !== "23505") throw error;
    }
    return raised;
  }
  const detail = String(Math.round(reading.usedPercent * 10) / 10);
  if (reading.usedPercent >= SIGNUP_PAUSE_PERCENT) {
    const res = await db.query(SIGNUP_PAUSE_SQL, [detail]);
    if (res.rows.length > 0) raised.push("disk_80");
  }
  if (reading.usedPercent >= PUBLISH_PAUSE_PERCENT) {
    const res = await db.query(PUBLISH_PAUSE_SQL, [detail]);
    if (res.rows.length > 0) raised.push("disk_90");
  }
  return raised;
}

// Reads the host status file and checks it. An unset path is one alert, never
// a failure.
export async function checkDiskStatusFile(
  db: Db,
  path: string | null,
): Promise<string[]> {
  return checkDisk(db, await readDiskStatus(path));
}

function clearSql(flag: ServiceFlag): string {
  switch (flag) {
    case "signup_paused":
      return `WITH cleared AS (
  UPDATE service_limits SET signup_paused = false
   WHERE id AND signup_paused
  RETURNING 1
)
INSERT INTO audit_log (actor_account_id, action, target, reason)
SELECT $1::uuid, 'service.flag_clear', 'signup_paused', $2::text FROM cleared
RETURNING id`;
    case "publish_paused_non_internal":
      return `WITH cleared AS (
  UPDATE service_limits SET publish_paused_non_internal = false
   WHERE id AND publish_paused_non_internal
  RETURNING 1
)
INSERT INTO audit_log (actor_account_id, action, target, reason)
SELECT $1::uuid, 'service.flag_clear', 'publish_paused_non_internal', $2::text
  FROM cleared
RETURNING id`;
    default:
      throw new Error("unknown service flag");
  }
}

// The only thing that clears a flag. There is no HTTP admin route yet: the
// maintainer role can also clear a flag, so "only a logged admin action
// clears" holds by convention (docs/KNOWN-GAPS.md). Returns true if the flag
// was set and is now clear; the audit row is written in the same statement.
export async function clearServiceFlag(
  db: Db,
  flag: ServiceFlag,
  actorId: string | null,
  reason: string,
): Promise<boolean> {
  const res = await db.query(clearSql(flag), [actorId, reason]);
  return res.rows.length > 0;
}
