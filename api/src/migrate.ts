import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const MIGRATIONS_DIR = fileURLToPath(new URL("../migrations", import.meta.url));
const FILE_PATTERN = /^\d{4}_[a-z0-9_]+\.sql$/;
// Any fixed number: keeps two runners from applying migrations at once.
const LOCK_ID = 4815162342;

// Applies NNNN_name.sql files in order and records each in schema_migrations.
// Run it as pingzo_owner. Returns the names applied by this call.
export async function runMigrations(
  connectionString: string,
  dir: string = MIGRATIONS_DIR,
): Promise<string[]> {
  const files = readdirSync(dir)
    .filter((name) => FILE_PATTERN.test(name))
    .sort();
  const client = new pg.Client({ connectionString });
  await client.connect();
  const applied: string[] = [];
  try {
    await client.query("SELECT pg_advisory_lock($1)", [LOCK_ID]);
    await client.query(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         name text PRIMARY KEY,
         checksum text NOT NULL,
         applied_at timestamptz NOT NULL DEFAULT now()
       )`,
    );
    const done = await client.query<{ name: string; checksum: string }>(
      "SELECT name, checksum FROM schema_migrations",
    );
    const known = new Map(done.rows.map((row) => [row.name, row.checksum]));
    for (const name of files) {
      const sql = readFileSync(join(dir, name), "utf8");
      const checksum = createHash("sha256").update(sql).digest("hex");
      const previous = known.get(name);
      if (previous !== undefined) {
        if (previous !== checksum) {
          throw new Error(`Migration ${name} changed after it was applied`);
        }
        continue;
      }
      try {
        await client.query("BEGIN");
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)",
          [name, checksum],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
      applied.push(name);
    }
  } finally {
    await client.end();
  }
  return applied;
}

async function main(): Promise<void> {
  const url = process.env.PINGZO_MIGRATE_URL;
  if (url === undefined || url === "") {
    throw new Error("PINGZO_MIGRATE_URL (pingzo_owner) is required");
  }
  const applied = await runMigrations(url);
  console.log(`migrations applied: ${applied.length}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    // Print the message only: connection errors can echo the URL.
    console.error(error instanceof Error ? error.name : "migration failed");
    process.exit(1);
  });
}
