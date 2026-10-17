import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import type { GlobalSetupContext } from "vitest/node";
import { runMigrations } from "../../src/migrate.ts";

declare module "vitest" {
  export interface ProvidedContext {
    dbUrl: string;
    // pingzo_owner, for tests that must change a limit the app cannot change.
    ownerUrl: string;
    logFile: string;
    secretsFile: string;
  }
}

const BOOTSTRAP_SQL = fileURLToPath(
  new URL("../bootstrap-roles.sql", import.meta.url),
);

type RoleRow = { rolsuper: boolean; rolbypassrls: boolean };

function urlFor(base: string, database: string, user?: string, pw?: string) {
  const url = new URL(base);
  url.pathname = `/${database}`;
  if (user !== undefined && pw !== undefined) {
    url.username = user;
    url.password = pw;
  }
  return url.toString();
}

async function asSuperuser(url: string, sql: string): Promise<void> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

// CI harness contract: with PINGZO_TEST_SUPERUSER_URL, create a fresh database,
// run the role bootstrap, set random passwords, run migrations as
// pingzo_owner. Tests then connect as pingzo_app only.
export default async function setup({
  provide,
}: GlobalSetupContext): Promise<() => Promise<void>> {
  const superUrl = process.env.PINGZO_TEST_SUPERUSER_URL;
  if (superUrl === undefined || superUrl === "") {
    throw new Error("PINGZO_TEST_SUPERUSER_URL is required");
  }
  const database = `pingzo_test_${randomBytes(6).toString("hex")}`;
  // Hex only, so inlining into ALTER ROLE is safe.
  const ownerPassword = randomBytes(24).toString("hex");
  const appPassword = randomBytes(24).toString("hex");

  await asSuperuser(superUrl, `CREATE DATABASE "${database}"`);
  const bootstrap = readFileSync(BOOTSTRAP_SQL, "utf8");
  await asSuperuser(
    urlFor(superUrl, database),
    `${bootstrap}
     ALTER ROLE pingzo_owner PASSWORD '${ownerPassword}';
     ALTER ROLE pingzo_app PASSWORD '${appPassword}';`,
  );
  await runMigrations(
    urlFor(superUrl, database, "pingzo_owner", ownerPassword),
  );
  // The superuser step of the role bootstrap, after the migrations: pingzo_owner
  // keeps no membership of pingzo_keyresolver.
  await asSuperuser(
    urlFor(superUrl, database),
    "REVOKE pingzo_keyresolver FROM pingzo_owner",
  );

  // Fail fast if the app role is ever privileged (T-ROLE repeats this check).
  const appUrl = urlFor(superUrl, database, "pingzo_app", appPassword);
  const probe = new pg.Client({ connectionString: appUrl });
  await probe.connect();
  try {
    const role = await probe.query<RoleRow>(
      "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
    );
    if (
      role.rows[0]?.rolsuper !== false ||
      role.rows[0].rolbypassrls !== false
    ) {
      throw new Error("pingzo_app must be NOSUPERUSER and NOBYPASSRLS");
    }
  } finally {
    await probe.end();
  }

  const dir = mkdtempSync(join(tmpdir(), "pingzo-test-"));
  const logFile = join(dir, "app.log");
  const secretsFile = join(dir, "secrets.txt");
  writeFileSync(logFile, "");
  writeFileSync(secretsFile, "");

  provide("dbUrl", appUrl);
  provide(
    "ownerUrl",
    urlFor(superUrl, database, "pingzo_owner", ownerPassword),
  );
  provide("logFile", logFile);
  provide("secretsFile", secretsFile);

  return async () => {
    rmSync(dir, { recursive: true, force: true });
    await asSuperuser(
      superUrl,
      `DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`,
    );
  };
}
