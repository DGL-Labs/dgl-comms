import { createHash, randomBytes } from "node:crypto";

// 32 random bytes, base64url. Used for magic links and refresh tokens.
export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

// Only this SHA-256 is stored; the token itself goes to the user once.
export function hashToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}
