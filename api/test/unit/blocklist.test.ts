import { describe, expect, it } from "vitest";
import { isBlockedDomain, loadBlocklist } from "../../src/blocklist.ts";
import { loadConfig } from "../../src/config.ts";

describe("blocklist", () => {
  it("matches a listed domain and its subdomains, case-insensitively", () => {
    const list = new Set(["bad.example", "worse.test"]);
    expect(isBlockedDomain(list, "bad.example")).toBe(true);
    expect(isBlockedDomain(list, "BAD.example")).toBe(true);
    expect(isBlockedDomain(list, "mail.worse.test")).toBe(true);
    expect(isBlockedDomain(list, "good.example")).toBe(false);
    expect(isBlockedDomain(list, "example")).toBe(false);
  });

  it("loads the committed list", () => {
    const config = loadConfig({
      PINGZO_JWT_KEY: "x".repeat(32),
      PINGZO_DATABASE_URL: "postgres://unused",
    });
    const list = loadBlocklist(config.blocklistPath);
    expect(list.size).toBeGreaterThan(9000);
    expect(list.has("0-mail.com")).toBe(true);
  });
});
