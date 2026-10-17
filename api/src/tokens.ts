import { createHash, randomBytes } from "node:crypto";

// 32 random bytes, base64url. Used for magic links and refresh tokens.
export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

const KEY_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

// A topic key id: "pz_" and 8 characters of lowercase base32 (5 random bytes,
// 40 bits), the form the topic_keys check and resolve_topic_key accept.
export function newKeyId(): string {
  let id = "";
  let acc = 0;
  let bits = 0;
  for (const byte of randomBytes(5)) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      id += KEY_ID_ALPHABET.charAt((acc >> bits) & 31);
    }
    acc &= (1 << bits) - 1;
  }
  return `pz_${id}`;
}

// Only this SHA-256 is stored; the token itself goes to the user once.
export function hashToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}
