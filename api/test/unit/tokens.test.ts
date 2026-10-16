import { describe, expect, it } from "vitest";
import { hashToken, newToken } from "../../src/tokens.ts";

describe("tokens", () => {
  it("makes 32 random bytes as base64url", () => {
    const token = newToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, "base64url")).toHaveLength(32);
    expect(newToken()).not.toBe(token);
  });

  it("hashes with SHA-256, deterministically", () => {
    const hash = hashToken("abc");
    expect(hash).toHaveLength(32);
    expect(hash.toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(hashToken("abc").equals(hash)).toBe(true);
    expect(hashToken("abd").equals(hash)).toBe(false);
  });
});
