import { buildApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { createPool } from "./db.ts";
import { TestSink } from "./email.ts";
import { createLogger } from "./log.ts";

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const pool = createPool(config.databaseUrl);
  // C-1b has no real email provider: TestSink only records in memory, so a
  // running server sends nothing. A provider arrives in a later task.
  const app = buildApp({ pool, config, sender: new TestSink() });
  await app.listen({ host: config.host, port: config.port });
  createLogger().log({ event: "startup" });
}

main().catch((error: unknown) => {
  // Name only: messages from config or the database could echo values.
  const reason = error instanceof Error ? error.name : "unknown";
  createLogger().log({ event: "startup_failed", reason });
  process.exit(1);
});
