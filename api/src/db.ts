import pg from "pg";
import type { Pool, QueryResult, QueryResultRow } from "pg";

// The part of a pool or a transaction client that the service code uses.
export interface Db {
  query<R extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<R>>;
}

// The api's share of the connection budget (docs/DB-ROLES.md): 8 connections,
// a 2 second wait for one, and timeouts on every connection. A lock wait over
// lock_timeout raises SQLSTATE 55P03; a wait for a connection over
// connectionTimeoutMillis rejects with POOL_TIMEOUT_MESSAGE. Both end as 503
// busy (isBusyError, and the error handler in app.ts).
export function createPool(connectionString: string): Pool {
  return new pg.Pool({
    connectionString,
    max: 8,
    connectionTimeoutMillis: 2000,
    options:
      "-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000",
  });
}

// What pg rejects with when no connection came free in time.
const POOL_TIMEOUT_MESSAGE = "timeout exceeded when trying to connect";

// A lock wait that timed out, or a pool that had no free connection in time:
// both are retryable.
export function isBusyError(error: unknown): boolean {
  if (pgCode(error) === "55P03") return true;
  return error instanceof Error && error.message === POOL_TIMEOUT_MESSAGE;
}

export async function withTx<T>(
  pool: Pool,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// What a request may touch, as row-level security sees it. Only the helpers in
// this file set it, and only with SET LOCAL semantics (set_config with
// is_local = true), so it ends with the transaction and never leaks to the
// next user of a pooled connection.
export interface Scope {
  // Adds workspaces to the context after the caller has been shown to belong
  // to them some other way: a workspace this transaction just made, one that
  // a valid invitation names, or one the caller owns.
  addWorkspaces(workspaceIds: string[]): Promise<void>;
  // Cuts the context down to one workspace: that workspace if it is already in
  // the context, otherwise the empty list. It never adds a workspace.
  narrowTo(workspaceId: string): Promise<void>;
}

export interface RequestContext {
  accountId: string;
  // Only for accepting an invitation: the SHA-256 of the token the caller
  // holds. It opens that one invitation row and nothing else.
  inviteHash?: Buffer;
}

async function setWorkspaceIds(tx: Db, ids: string[]): Promise<void> {
  for (const id of ids) {
    if (!UUID.test(id)) throw new Error("bad workspace id");
  }
  await tx.query("SELECT set_config('app.workspace_ids', $1, true)", [
    `{${ids.join(",")}}`,
  ]);
}

// Sets the context for the current transaction, in this order: the account,
// then the caller's memberships are read, then the workspace list. The
// transaction must already be open. Prefer withContext.
export async function loadContext(
  tx: Db,
  accountId: string,
  inviteHash?: Buffer,
): Promise<Scope> {
  if (!UUID.test(accountId)) throw new Error("bad account id");
  await tx.query("SELECT set_config('app.account_id', $1, true)", [accountId]);
  if (inviteHash !== undefined) {
    await tx.query("SELECT set_config('app.invite_hash', $1, true)", [
      inviteHash.toString("hex"),
    ]);
  }
  const memberships = await tx.query<{ workspace_id: string }>(
    "SELECT workspace_id FROM members WHERE account_id = $1",
    [accountId],
  );
  const ids = memberships.rows.map((row) => row.workspace_id);
  await setWorkspaceIds(tx, ids);
  return {
    async addWorkspaces(workspaceIds) {
      for (const id of workspaceIds) {
        if (!ids.includes(id)) ids.push(id);
      }
      await setWorkspaceIds(tx, ids);
    },
    async narrowTo(workspaceId) {
      const keep = ids.includes(workspaceId) ? [workspaceId] : [];
      ids.splice(0, ids.length, ...keep);
      await setWorkspaceIds(tx, ids);
    },
  };
}

// The one way a signed-in caller reaches the data tables.
export function withContext<T>(
  pool: Pool,
  who: RequestContext,
  fn: (tx: Db, scope: Scope) => Promise<T>,
): Promise<T> {
  return withTx(pool, async (tx) => {
    const scope = await loadContext(tx, who.accountId, who.inviteHash);
    return fn(tx, scope);
  });
}

// For a route on /v1/workspaces/:id/...: the context is the path workspace
// intersected with the caller's memberships. A member sees that one workspace;
// a non-member sees none. It never adds a workspace, so a skipped or broken
// permission check still reaches nothing of another workspace.
export function withPathContext<T>(
  pool: Pool,
  who: RequestContext,
  workspaceId: string,
  fn: (tx: Db, scope: Scope) => Promise<T>,
): Promise<T> {
  return withContext(pool, who, async (tx, scope) => {
    await scope.narrowTo(workspaceId);
    return fn(tx, scope);
  });
}

export interface ResolvedKey {
  topicId: string;
  workspaceId: string;
}

// The one way a topic key reaches the data tables. resolve_topic_key is the
// only statement that runs before the context. A key that does not resolve
// gets null and fn never runs.
export function withKeyContext<T>(
  pool: Pool,
  keyId: string,
  keyHash: Buffer,
  fn: (tx: Db, key: ResolvedKey) => Promise<T>,
): Promise<T | null> {
  return withTx(pool, async (tx) => {
    const found = await tx.query<{ topic_id: string; workspace_id: string }>(
      "SELECT * FROM resolve_topic_key($1, $2)",
      [keyId, keyHash],
    );
    const row = first(found.rows);
    if (row === undefined) return null;
    await setWorkspaceIds(tx, [row.workspace_id]);
    return fn(tx, { topicId: row.topic_id, workspaceId: row.workspace_id });
  });
}

// A short transaction whose context is exactly one workspace. For work that
// has no caller of its own, such as loading a message for a stream: the
// workspace comes from state the server recorded, never from a notification.
export function withWorkspaceTx<T>(
  pool: Pool,
  workspaceId: string,
  fn: (tx: Db) => Promise<T>,
): Promise<T> {
  return withTx(pool, async (tx) => {
    await setWorkspaceIds(tx, [workspaceId]);
    return fn(tx);
  });
}

export interface Listener {
  close(): Promise<void>;
}

export type ListenChannel = "pingzo_msg" | "pingzo_acl";

// The application_name of the LISTEN connection. A test finds the backend by it.
export const LISTEN_APPLICATION_NAME = "pingzo_listen";

// One LISTEN connection: a direct connection that is not part of the pool, on
// pingzo_msg (a message was published) and pingzo_acl (access changed).
// onNotify gets the channel and the raw payload, which is a hint and nothing
// more. onDown runs once when the connection fails or ends; this function does
// not reconnect (the caller starts a new one).
export async function startListener(
  connectionString: string,
  onNotify: (channel: ListenChannel, payload: string) => void,
  onDown: () => void,
): Promise<Listener> {
  const client = new pg.Client({
    connectionString,
    application_name: LISTEN_APPLICATION_NAME,
  });
  let closing = false;
  let down = false;
  // A failure before both LISTENs are in place is thrown by this function
  // instead of reported through onDown.
  let ready = false;
  const failed = () => {
    if (closing || down || !ready) return;
    down = true;
    client.end().catch(() => undefined);
    onDown();
  };
  client.on("notification", (message) => {
    if (closing || down) return;
    if (message.channel === "pingzo_msg" || message.channel === "pingzo_acl") {
      onNotify(message.channel, message.payload ?? "");
    }
  });
  client.on("error", failed);
  client.on("end", failed);
  try {
    await client.connect();
    await client.query("LISTEN pingzo_msg");
    await client.query("LISTEN pingzo_acl");
    ready = true;
  } catch (error) {
    closing = true;
    await client.end().catch(() => undefined);
    throw error;
  }
  return {
    async close() {
      closing = true;
      await client.end().catch(() => undefined);
    },
  };
}

// One statement in a transaction of its own, for the counters (rate_buckets and
// the usage tables hold numbers, not tenant rows, and have no row-level
// security). It commits at once, so a debit stays even if the request fails
// later.
export function autocommit<R extends QueryResultRow = QueryResultRow>(
  pool: Pool,
  text: string,
  values?: unknown[],
): Promise<QueryResult<R>> {
  return pool.query<R>(text, values);
}

// Test hook (AppDeps.testHooks.lockTimeoutMs): for this transaction only, lock
// waits last this long. statement_timeout follows, so that a wait this long is
// not cut short by it.
export async function setLockTimeout(tx: Db, ms: number): Promise<void> {
  const wait = Math.max(0, Math.floor(ms));
  await tx.query("SELECT set_config('lock_timeout', $1, true)", [`${wait}ms`]);
  await tx.query("SELECT set_config('statement_timeout', $1, true)", [
    `${wait + 5000}ms`,
  ]);
}

// Test hook (AppDeps.testHooks.holdAfterSeqMs): holds the transaction open for
// ms, with the statement and idle-in-transaction timeouts off on this
// transaction's connection only.
export async function holdTx(tx: Db, ms: number): Promise<void> {
  await tx.query("SELECT set_config('statement_timeout', '0', true)");
  await tx.query(
    "SELECT set_config('idle_in_transaction_session_timeout', '0', true)",
  );
  await tx.query("SELECT pg_sleep($1::float8)", [ms / 1000]);
}

// The SQLSTATE of a database error, if it has one.
export function pgCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

export function first<R>(rows: R[]): R | undefined {
  return rows[0];
}
