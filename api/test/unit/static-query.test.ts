import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../../src", import.meta.url));
// The only files that may talk to a pool or client directly.
const ALLOWED = new Set(["db.ts", "migrate.ts"]);

function code(name: string): string {
  return readFileSync(join(SRC, name), "utf8")
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");
}

const files = readdirSync(SRC).filter(
  (name) => name.endsWith(".ts") && !ALLOWED.has(name),
);

// Static-query check: all data access goes through withTx, withContext or
// withKeyContext in db.ts, so the request context cannot be skipped.
describe("static query check", () => {
  it("finds the source files", () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it("has no direct .query( on a pool or client outside db.ts", () => {
    for (const name of files) {
      expect(code(name), name).not.toMatch(/\b(pool|client)\.query\s*\(/i);
    }
  });

  it("opens no connection outside db.ts", () => {
    for (const name of files) {
      expect(code(name), name).not.toMatch(/\.connect\s*\(/);
    }
  });

  it("sets the request context only in db.ts", () => {
    for (const name of files) {
      const text = code(name);
      expect(text, name).not.toMatch(/set_config|SET\s+LOCAL|SET\s+SESSION/i);
      expect(text, name).not.toMatch(/app\.(workspace_ids|account_id)/);
    }
  });
});
