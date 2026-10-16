import { SignJWT, jwtVerify } from "jose";
import type { Db } from "./db.ts";
import { first } from "./db.ts";
import { hashToken, newToken } from "./tokens.ts";

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface IssuedSession {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export function signAccessToken(
  key: Uint8Array,
  accountId: string,
  sessionId: string,
  now: Date,
): Promise<string> {
  const iat = Math.floor(now.getTime() / 1000);
  return new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(accountId)
    .setIssuedAt(iat)
    .setExpirationTime(iat + ACCESS_TTL_SECONDS)
    .sign(key);
}

// Returns the account and session ids from a valid access token, else null.
export async function readAccessToken(
  key: Uint8Array,
  token: string,
  now: Date,
): Promise<{ accountId: string; sessionId: string } | null> {
  try {
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["HS256"],
      currentDate: now,
    });
    const sid = payload.sid;
    if (typeof payload.sub !== "string" || typeof sid !== "string") return null;
    return { accountId: payload.sub, sessionId: sid };
  } catch {
    return null;
  }
}

export async function createSession(
  db: Db,
  key: Uint8Array,
  accountId: string,
  now: Date,
  deviceId: string | null = null,
): Promise<IssuedSession> {
  const refreshToken = newToken();
  const expiresAt = new Date(now.getTime() + REFRESH_TTL_MS);
  const result = await db.query<{ id: string }>(
    `INSERT INTO sessions (account_id, refresh_hash, device_id, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [accountId, hashToken(refreshToken), deviceId, expiresAt, now],
  );
  const row = first(result.rows);
  if (row === undefined) throw new Error("session insert returned no row");
  return {
    sessionId: row.id,
    accessToken: await signAccessToken(key, accountId, row.id, now),
    refreshToken,
    expiresIn: ACCESS_TTL_SECONDS,
  };
}

// Revokes one session. Returns the ids actually revoked (0 or 1).
export async function revokeSession(
  db: Db,
  sessionId: string,
  now: Date,
): Promise<string[]> {
  const result = await db.query<{ id: string }>(
    `UPDATE sessions SET revoked_at = $2
      WHERE id = $1 AND revoked_at IS NULL RETURNING id`,
    [sessionId, now],
  );
  return result.rows.map((row) => row.id);
}

// Revokes every live session of an account. Returns the ids revoked.
export async function revokeAllSessions(
  db: Db,
  accountId: string,
  now: Date,
): Promise<string[]> {
  const result = await db.query<{ id: string }>(
    `UPDATE sessions SET revoked_at = $2
      WHERE account_id = $1 AND revoked_at IS NULL RETURNING id`,
    [accountId, now],
  );
  return result.rows.map((row) => row.id);
}
