# C-1c task: workspaces, members, roles, invitations, row-level security, key context

The builder (Claude Code Action) works from this file. Scope is C-1c only: C1-PLAN-r4 §8 row C-1c with ADDENDUM-1, plus C1C-TASK-LIST-r1 and its ADDENDUM-1 and -2, under Taylor's C-1c go. **This is the isolation step and is security-critical:** prefer simple, explicit code and fail closed.

## Hard rules (as C-1b, plus)
- No secrets. Config comes from env. Tests use `@example.test` addresses only. Logs have fixed fields only.
- **Migrations are add-only** (`0003_…` onward, run as `pingzo_owner`). **Every migration states its grants explicitly.** Do not rely on default privileges.
- **Do not edit `.github/` or `package-lock.json`.** Add **no new dependencies**. If one is truly needed, say so in the summary instead.
- **Email** goes through `EmailSender` and `TestSink` only.
- **Do not weaken an existing C-1b test.**

## A0. Known gaps into the repo
- Rename `docs/KNOWN-GAPS-C1B.md` to `docs/KNOWN-GAPS.md` and keep its content under a heading "C-1b (G5 round 1)".
- Add a section "C-1b (G5 round 2)" with these six points:
  1. Link exhaustion: any IP can use up an account's 3 login links per 15 minutes, which voids the pending link. Re-sending sign-up voids an unverified account's verify link, limited only by the per-IP cap. Fix candidate in C-1g: exempt the most recent link from voiding, or a per-account cap plus a cool-off.
  2. Shared IP budget: login and redeem share 20 per IP per 15 minutes, so users behind one NAT can lock each other out, and `login_failures` grows by one row per login. Fix candidates in C-1g: separate budgets, IPv6 /64 grouping, retention.
  3. Sign-up timing: sign-up for an existing verified email skips the send. This adds to the login timing gap.
  4. `PINGZO_JWT_KID` defaults to `k1`. The deploy step (C-1k) must set it deliberately when the key is rotated.
  5. Row-level security was not in C-1b. It arrives in C-1c (this step).
  6. Default table privileges are unchanged. Each new migration states its grants.
- Add a section "C-1c" for any gaps you leave in this step.

## Data (migration `0003`; r4 §3 is the source, and r3 only where r4 says "as r3")
| Table | Columns |
|---|---|
| `workspaces` (r4) | `id` uuid pk, `owner_id` uuid not null → accounts, `kind` text not null check in (`client`, `team`, `dgl_internal`), `status` text not null default `active` check in (`active`, `suspended`), `created_at`. **Plus `name`** text not null (1–60 characters). **`name` is new:** r4's row has no name, but the app needs one. This is noted in the PR for G5 |
| `workspace_limits` (r3, because r4 says "as r3") | `workspace_id` pk → workspaces, `max_topics` 3, `max_members` 5, `max_keys` 5, `msgs_per_day` 1000, `msgs_per_min` 60, `max_body_bytes` 2048, `retention_days` 30 (defaults as shown) |
| `members` (r3) | `workspace_id`, `account_id`, `role` text check in (`owner`, `admin`, `member`), `created_at`; pk (`workspace_id`, `account_id`); exactly one `owner` per workspace (partial unique index). **r3 also lists `viewer`.** C1C ADDENDUM-2 defines three roles, so `viewer` is omitted and noted in the PR |
| `invitations` (r3) | `id` uuid pk, `workspace_id`, `invited_by` → accounts, `email` citext, `role` (`admin` or `member`), `token_hash` bytea unique, `expires_at` (7 days), `used_at`, `created_at` |
| `service_limits` (r4, minimal) | a single row (`id` boolean pk default true, check id), `max_workspaces_total` int not null default 2000. The other r4 columns come at C-1d |
| `topic_keys` (r4, **minimal** per C1C ADD-1 D2) | `id` text pk check `^pz_[a-z2-7]{8}$`, `key_hash` bytea not null, `topic_id` uuid not null, `workspace_id` uuid not null → workspaces, `expires_at` timestamptz null, `revoked_at` timestamptz null, `created_at`. No `topics` table yet, so no FK on `topic_id` (C-1d adds `topics` and the composite FK) |
| `audit_log` | `id` bigserial, `at` timestamptz default now(), `actor_account_id` uuid null, `workspace_id` uuid null, `action` text not null, `target` text null (an id only, never an email), `reason` text null |

## Roles and permissions (C1C ADD-2: one data table, enforced on the server)
Create `api/src/permissions.ts`, exporting one table that maps each action to the roles allowed. Every route checks it, and nothing else decides permissions.

| Action | owner | admin | member |
|---|---|---|---|
| `workspace.read` (read topics and messages; later steps) | ✓ | ✓ | ✓ |
| `message.post` (later step) | ✓ | ✓ | ✓ |
| `settings.own_notifications` | ✓ | ✓ | ✓ |
| `report_block` (later step) | ✓ | ✓ | ✓ |
| `invite.create`, `invite.cancel` | ✓ | ✓ | |
| `member.add_remove` (never the owner) | ✓ | ✓ | |
| `member.change_role` (never the owner's) | ✓ | ✓ | |
| `topic.manage` (later step) | ✓ | ✓ | |
| `key.manage` (later step) | ✓ | ✓ | |
| `workspace.settings` (rename) | ✓ | ✓ | |
| `workspace.transfer_ownership` | ✓ | | |
| `workspace.delete` | ✓ | | |
| remove the owner | nobody; transfer first | | |

## Database roles and RLS (migration `0003`)
- **`pingzo_keyresolver`:**
  - NOLOGIN and BYPASSRLS;
  - grants: SELECT on `topic_keys`, and SELECT (`id`, `status`) on `workspaces`, and nothing else;
  - it owns only the function below.
- **`pingzo_app`** stays NOSUPERUSER and NOBYPASSRLS, with DML only and narrowed per table:
  - `audit_log`: INSERT and SELECT only (append-only by grants);
  - `topic_keys`: SELECT, INSERT, UPDATE and DELETE, subject to RLS.
- **RLS with FORCE** on `members`, `invitations` and `topic_keys`. Create a SQL helper function, or a documented policy template, so C-1d and later steps reuse the exact form:
  - **USING and WITH CHECK** (identical): `workspace_id = ANY (coalesce(nullif(current_setting('app.workspace_ids', true), ''), '{}')::uuid[])`.
  - **`members` adds** to USING (only): `OR account_id = nullif(current_setting('app.account_id', true), '')::uuid`, so a caller can read its own memberships to build the context. WITH CHECK stays workspace-only.
- **Without RLS, with narrowed grants:** `workspaces`, `workspace_limits` and `service_limits`. The app reads `workspaces` only by id after the membership check. `service_limits` is SELECT only for the app.
- **Function `resolve_topic_key(key_id text, key_hash bytea) RETURNS TABLE(topic_id uuid, workspace_id uuid)`:**
  - owned by `pingzo_keyresolver`;
  - `SECURITY DEFINER`, `SET search_path = pg_catalog, pg_temp`;
  - every name schema-qualified (`public.topic_keys`, `public.workspaces`);
  - `REVOKE EXECUTE … FROM PUBLIC`, `GRANT EXECUTE … TO pingzo_app`;
  - returns a row only if the id matches `^pz_[a-z2-7]{8}$`, the hash matches, `revoked_at IS NULL`, `expires_at` is null or in the future, and the workspace `status = 'active'`.
- **Harness bootstrap** (test only): the bootstrap SQL creates `pingzo_keyresolver` like the other roles.

## Request context (A6)
- Create one helper, e.g. `withContext(pool, {accountId}, fn)` in `api/src/db.ts`. It opens a transaction and runs, in order:
  1. `SELECT set_config('app.account_id', $1, true)`;
  2. reads the caller's memberships;
  3. `SELECT set_config('app.workspace_ids', $2, true)` with the caller's workspace ids;
  4. runs `fn`.

  It is never set at session level.
- **Key callers** use `withKeyContext(pool, keyId, keyHash, fn)`:
  1. begin;
  2. `SELECT * FROM resolve_topic_key($1,$2)`, the only statement allowed before the context;
  3. set `app.workspace_ids` to that one workspace;
  4. run `fn`.

  No route uses it yet, but tests exercise it.
- **Static check (unit test):** fail if any file in `api/src/` other than `db.ts` and the migration runner calls `.query(` on a pool or client directly.

## Endpoints (all authenticated; every one checks the permission table)
- `POST /v1/workspaces {name, kind}`:
  - `kind` is `client` or `team` only; `dgl_internal` is never created through the API;
  - in one transaction, it takes the caller's account row FOR UPDATE, refuses a 4th workspace with 409, and returns 503 if the `max_workspaces_total` ceiling is reached;
  - it creates the workspace, its `workspace_limits` row, the owner membership and an audit row.
- `GET /v1/workspaces` (the caller's own), `GET /v1/workspaces/:id`, `PATCH /v1/workspaces/:id {name}` (needs `workspace.settings`), `DELETE /v1/workspaces/:id` (owner only).
- `GET /v1/workspaces/:id/members`, `PATCH /v1/workspaces/:id/members/:accountId {role}`, `DELETE /v1/workspaces/:id/members/:accountId` (never the owner). Members may also leave themselves; the owner cannot.
- `POST /v1/workspaces/:id/transfer {accountId}` (owner only; the target must be a member).
- **Invitations:**
  - `POST /v1/workspaces/:id/invitations {email, role}`:
    - caps: 20 a day per inviting account, 50 a day per workspace, and `max_members` counting pending invites;
    - the fixed email text, through the sink, carries the token only, with no workspace name or user text;
    - the token is 32 random bytes; only its SHA-256 is stored; 7 days; single-use.
  - `DELETE …/invitations/:inviteId` (cancel).
  - `POST /v1/invitations/accept {token}`: the caller's verified email must equal the invite email. Before acceptance nothing about the workspace is revealed: the reply is the workspace id only after success.
- **Status codes:** cross-workspace access returns **404** (not 403), so workspace ids don't leak. A role denial inside one's own workspace returns **403**.
- **Audit (fixed fields):** workspace create, rename, delete, transfer, role change, member removal, invite create, cancel and accept.

## Account deletion (A9, extending `deleteAccount`)
- **The first call** `DELETE /v1/account` returns **409** with `{owned_workspaces:[{id, action}]}` when the caller owns workspaces, where `action` is:
  - `transfer`: to the longest-standing admin, else the longest-standing member;
  - `delete`: there are no other members.
- **Repeating with `?confirm=true`** performs those actions in the same transaction as the account deletion, and also removes all of the caller's memberships. Audit rows are written.

## Tests (keep all C-1b tests green)
- **T-ROLE** (extend): the `pingzo_app` flags as before. `pingzo_keyresolver`: `rolcanlogin` false, `rolbypassrls` true, and it owns exactly one object (the function).
- **T-RLS**, as `pingzo_app` through raw queries:
  - context = A: zero rows of B from `members`, `invitations` and `topic_keys`;
  - context missing or empty: zero rows;
  - WITH CHECK: inserting a B row with context A fails, and updating an A row's `workspace_id` to B fails;
  - a deliberately broken app check (a route test that skips the permission check through a test hook) still gets no B rows.
- **T-KEYCTX**, as `pingzo_app`:
  - a valid key resolves;
  - expired, revoked, suspended-workspace and malformed-id keys return no row;
  - a direct `SELECT` on `topic_keys` with no context returns 0 rows;
  - `has_function_privilege('public', 'resolve_topic_key(text,bytea)', 'EXECUTE')` is false;
  - `withKeyContext` then sees exactly that one workspace.
- **Cross-workspace deny:** a member of A gets 404 on every B endpoint; an invite token for B cannot be used to join A.
- **Role deny (ADD-2):**
  - a member gets 403 on invite, remove, role change, rename, transfer and delete;
  - an admin gets 403 on transfer and delete, and on removing or demoting the owner;
  - the owner cannot leave or remove themself.
- **T-INVITE-CAPS:** the 21st invite in a day per account and the 51st per workspace are refused; reused, expired, cancelled and wrong-email invites fail; `max_members` is respected.
- **T-WS-CAPS:** the 4th workspace for an account gets 409; the global ceiling (set low in the test) gets 503.
- **T-AUDIT:** each action writes exactly one row; `pingzo_app` UPDATE and DELETE on `audit_log` fail.
- **T-DELETE-CASCADE** (extend): the 409 warning lists the right actions; the confirm path transfers to the right member or deletes; memberships are gone.
- **T-LOGS:** still clean, including no invite tokens or invitee emails.
- **Static-query check** (unit).

## Done means
All of the above, with every test written. Commit in groups:
1. migration plus roles plus RLS;
2. the helpers and the static check;
3. workspaces and members;
4. invitations;
5. deletion;
6. tests;
7. `docs/KNOWN-GAPS.md`.

Post a summary that maps each section to its commit, and lists any point you were unsure about.
