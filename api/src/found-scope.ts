import type { Ctx } from "./context.ts";
import { withContext } from "./db.ts";
import type { Db } from "./db.ts";
import type { Action } from "./permissions.ts";
import { authorize } from "./workspaces.ts";

// For a route on a topic or a key, where the path does not name the workspace.
// In order: find the workspace inside the caller's membership context (a row
// of a workspace the caller is not in is not visible, so it is not found),
// authorize the action there, then narrow the context to that workspace. fn
// runs only after all three. A narrowing never adds a workspace.
export function inFoundWorkspace<T>(
  ctx: Ctx,
  accountId: string,
  find: (tx: Db) => Promise<string | undefined>,
  action: Action,
  fn: (tx: Db, workspaceId: string) => Promise<T>,
): Promise<T | { kind: "not_found" } | { kind: "forbidden" }> {
  return withContext(ctx.pool, { accountId }, async (tx, scope) => {
    const workspaceId = await find(tx);
    if (workspaceId === undefined) return { kind: "not_found" as const };
    const decision = await authorize(ctx, tx, accountId, workspaceId, action);
    if (decision.kind !== "ok") return decision;
    await scope.narrowTo(workspaceId);
    return fn(tx, workspaceId);
  });
}
