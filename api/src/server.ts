import { buildApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { createPool } from "./db.ts";
import { TestSink } from "./email.ts";
import { createLogger } from "./log.ts";

// A shutdown that takes longer than this is cut short.
const FORCE_EXIT_MS = 10_000;

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const pool = createPool(config.databaseUrl);
  // C-1b has no real email provider: TestSink only records in memory, so a
  // running server sends nothing. A provider arrives in a later task.
  const app = buildApp({ pool, config, sender: new TestSink() });
  await app.listen({ host: config.host, port: config.port });
  createLogger().log({ event: "startup" });
  // app.close() ends every open stream and closes the LISTEN client; without
  // it an open stream would hold the process up. If it hangs or fails, the
  // process still exits, with a reason code only.
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      const force = setTimeout(() => {
        createLogger().log({ event: "shutdown", reason: "shutdown_forced" });
        process.exit(1);
      }, FORCE_EXIT_MS);
      force.unref();
      app
        .close()
        .then(() => pool.end())
        .then(() => clearTimeout(force))
        .catch((error: unknown) => {
          const reason = error instanceof Error ? error.name : "unknown";
          createLogger().log({ event: "shutdown_failed", reason });
          process.exit(1);
        });
    });
  }
}

main().catch((error: unknown) => {
  // Name only: messages from config or the database could echo values.
  const reason = error instanceof Error ? error.name : "unknown";
  createLogger().log({ event: "startup_failed", reason });
  process.exit(1);
});
