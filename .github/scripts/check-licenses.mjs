// Dependency license allowlist (plan section 6). Reads every installed package under node_modules after
// `npm ci --ignore-scripts` and fails on any license outside the allowlist. No third-party code is used.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const ALLOWED = new Set(["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "CC0-1.0"]);
// Narrow, reviewed exceptions: exact package and version, development-only (never shipped), with the reason.
// Python-2.0 (PSF) is OSI-approved and permissive; argparse comes in through eslint -> js-yaml.
const DEV_EXCEPTIONS = new Map([["argparse@2.0.1", "Python-2.0"]]);
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const bad = [];
let checked = 0;

// Accepts a single SPDX id, or an OR-expression in which at least one side is allowed.
function ok(expr) {
  if (!expr || typeof expr !== "string") return false;
  const parts = expr.replace(/[()]/g, "").split(/\s+OR\s+/i).map((s) => s.trim());
  if (/\sAND\s/i.test(expr)) return expr.replace(/[()]/g, "").split(/\s+AND\s+/i).every((s) => ALLOWED.has(s.trim()));
  return parts.some((p) => ALLOWED.has(p));
}

for (const [path, meta] of Object.entries(lock.packages ?? {})) {
  if (path === "" || !path.includes("node_modules/")) continue;
  const pj = join(path, "package.json");
  let license = meta.license;
  if (!license && existsSync(pj)) {
    const p = JSON.parse(readFileSync(pj, "utf8"));
    license = typeof p.license === "string" ? p.license : p.license?.type;
  }
  checked++;
  const id = `${path.replace(/^.*node_modules\//, "")}@${meta.version ?? "?"}`;
  if (ok(license)) continue;
  if (meta.dev === true && DEV_EXCEPTIONS.get(id) === license) {
    console.log(`Exception (dev-only): ${id}: ${license}`);
    continue;
  }
  bad.push(`${id}: ${license ?? "none"}${meta.dev ? " (dev)" : " (RUNTIME)"}`);
}

console.log(`Checked ${checked} packages against: ${[...ALLOWED].join(", ")}`);
if (bad.length) {
  console.error("Not on the license allowlist:\n" + bad.join("\n"));
  process.exit(1);
}
console.log("All dependency licenses are on the allowlist.");
