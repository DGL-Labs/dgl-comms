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

export function first<R>(rows: R[]): R | undefined {
  return rows[0];
}
