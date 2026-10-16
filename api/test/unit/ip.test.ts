import { describe, expect, it } from "vitest";
import {
  normalizeIp,
  parseTrustedProxies,
  resolveClientIp,
} from "../../src/ip.ts";

const PROXIES = parseTrustedProxies("10.0.0.0/8, 2001:db8::/32");

describe("normalizeIp", () => {
  it("unwraps IPv4-mapped IPv6 and rejects non-IPs", () => {
    expect(normalizeIp("::ffff:10.1.2.3")).toBe("10.1.2.3");
    expect(normalizeIp("203.0.113.9")).toBe("203.0.113.9");
    expect(normalizeIp("not an ip")).toBeNull();
  });
});

describe("resolveClientIp", () => {
  it("uses the header when the peer is a trusted proxy", () => {
    expect(resolveClientIp("10.9.9.9", "203.0.113.9", PROXIES)).toBe(
      "203.0.113.9",
    );
    expect(resolveClientIp("::ffff:10.9.9.9", "203.0.113.9", PROXIES)).toBe(
      "203.0.113.9",
    );
    expect(resolveClientIp("2001:db8::1", "203.0.113.9", PROXIES)).toBe(
      "203.0.113.9",
    );
  });

  it("ignores the header when the peer is not trusted", () => {
    expect(resolveClientIp("198.51.100.7", "203.0.113.9", PROXIES)).toBe(
      "198.51.100.7",
    );
  });

  it("trusts nothing when the list is empty", () => {
    const none = parseTrustedProxies("");
    expect(resolveClientIp("10.9.9.9", "203.0.113.9", none)).toBe("10.9.9.9");
  });

  it("falls back to the peer for a missing or invalid header", () => {
    expect(resolveClientIp("10.9.9.9", undefined, PROXIES)).toBe("10.9.9.9");
    expect(resolveClientIp("10.9.9.9", "garbage", PROXIES)).toBe("10.9.9.9");
    expect(resolveClientIp("10.9.9.9", ["1.1.1.1"], PROXIES)).toBe("10.9.9.9");
  });

  it("falls back to 0.0.0.0 without a peer address", () => {
    expect(resolveClientIp(undefined, "203.0.113.9", PROXIES)).toBe("0.0.0.0");
  });
});

describe("parseTrustedProxies", () => {
  it("rejects bad entries", () => {
    expect(() => parseTrustedProxies("nope")).toThrow();
    expect(() => parseTrustedProxies("10.0.0.0/33")).toThrow();
    expect(() => parseTrustedProxies("10.0.0.0/8/8")).toThrow();
  });
});
