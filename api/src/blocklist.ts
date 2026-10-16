import { readFileSync } from "node:fs";

// Reads data/disposable-domains/blocklist.conf (one domain per line).
export function loadBlocklist(path: string): ReadonlySet<string> {
  const domains = readFileSync(path, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line !== "" && !line.startsWith("#"));
  return new Set(domains);
}

// True if the domain, or any parent domain of it, is on the list.
export function isBlockedDomain(
  blocklist: ReadonlySet<string>,
  domain: string,
): boolean {
  const labels = domain.toLowerCase().split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (blocklist.has(labels.slice(i).join("."))) return true;
  }
  return false;
}
