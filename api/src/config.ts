import { fileURLToPath } from "node:url";
import { parseTrustedProxies } from "./ip.ts";
import type { TrustedProxies } from "./ip.ts";

export interface Config {
  databaseUrl: string;
  jwtKey: string;
  jwtKid: string;
  allowlistOn: boolean;
  allowlist: ReadonlySet<string>;
  trustedProxies: TrustedProxies;
  blocklistPath: string;
  host: string;
  port: number;
}

export type Env = Record<string, string | undefined>;

const DEFAULT_BLOCKLIST_PATH = fileURLToPath(
  new URL("../../data/disposable-domains/blocklist.conf", import.meta.url),
);

function required(env: Env, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

// Configuration comes from environment variables only. Error messages name the
// variable and never print its value.
export function loadConfig(env: Env): Config {
  const jwtKey = required(env, "PINGZO_JWT_KEY");
  if (jwtKey.length < 32) {
    throw new Error("PINGZO_JWT_KEY must be at least 32 characters");
  }

  const jwtKid = (env.PINGZO_JWT_KID ?? "k1").trim();
  if (jwtKid === "") {
    throw new Error("PINGZO_JWT_KID must not be empty");
  }

  const flag = (env.PINGZO_ALLOWLIST_ON ?? "true").trim().toLowerCase();
  if (flag !== "true" && flag !== "false") {
    throw new Error("PINGZO_ALLOWLIST_ON must be true or false");
  }

  const allowlist = new Set(
    (env.PINGZO_TEAM_ALLOWLIST ?? "")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry !== ""),
  );

  const port = Number(env.PINGZO_PORT ?? "3000");
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("PINGZO_PORT must be a port number");
  }

  return {
    databaseUrl: required(env, "PINGZO_DATABASE_URL"),
    jwtKey,
    jwtKid,
    allowlistOn: flag === "true",
    allowlist,
    trustedProxies: parseTrustedProxies(env.PINGZO_TRUSTED_PROXIES ?? ""),
    blocklistPath: env.PINGZO_BLOCKLIST_PATH ?? DEFAULT_BLOCKLIST_PATH,
    host: env.PINGZO_HOST ?? "127.0.0.1",
    port,
  };
}
