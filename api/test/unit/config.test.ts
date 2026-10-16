import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config.ts";

const BASE = {
  PINGZO_JWT_KEY: "k".repeat(32),
  PINGZO_DATABASE_URL: "postgres://unused",
};

describe("loadConfig", () => {
  it("defaults the allowlist to on and trusts no proxy", () => {
    const config = loadConfig(BASE);
    expect(config.allowlistOn).toBe(true);
    expect(config.allowlist.size).toBe(0);
    expect(config.trustedProxies.check("127.0.0.1", "ipv4")).toBe(false);
  });

  it("reads the allowlist from the environment", () => {
    const config = loadConfig({
      ...BASE,
      PINGZO_TEAM_ALLOWLIST: " A@example.test, b@example.test ,",
      PINGZO_ALLOWLIST_ON: "false",
    });
    expect([...config.allowlist]).toEqual(["a@example.test", "b@example.test"]);
    expect(config.allowlistOn).toBe(false);
  });

  it("requires the JWT key and the database URL", () => {
    expect(() => loadConfig({ PINGZO_DATABASE_URL: "x" })).toThrow();
    expect(() => loadConfig({ ...BASE, PINGZO_JWT_KEY: "short" })).toThrow();
    const noUrl = { PINGZO_JWT_KEY: BASE.PINGZO_JWT_KEY };
    expect(() => loadConfig(noUrl)).toThrow();
  });

  it("does not put the JWT key in an error message", () => {
    const env = { ...BASE, PINGZO_JWT_KEY: "short-secret-value" };
    expect(() => loadConfig(env)).toThrow(/PINGZO_JWT_KEY/);
    expect(() => loadConfig(env)).not.toThrow(/short-secret-value/);
  });
});
