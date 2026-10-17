import pg from "pg";
import type { Pool, QueryResult, QueryResultRow } from "pg";

// The part of a pool or a transaction client that the service code uses.
export interface Db {
  query<R extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<R>>;
}

export function createPool(connectionString: string): Pool {
  return new pg.Pool({ connectionString, max: 10 });
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

export function first<R>(rows: R[]): R | undefined {
  return rows[0];
}
