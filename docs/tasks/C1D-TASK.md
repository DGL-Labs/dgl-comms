# C-1d task: topics, keys, publish, limits, disk guard, pool

The builder (Claude Code Action) works from this file. Scope is C-1d only: C1-PLAN-r4 §8 row C-1d (§2 engine and publish, §3 data model, limits and isolation, §4) with ADDENDUM-1, plus C1D-TASK-LIST-r1 and its ADDENDUM-1, under Taylor's C-1d go. Revision r2 applies the pre-build spec review (C1D-SPEC-REVIEW-1) and PC's rulings. The work is split into four runs; each run's comment names its groups. **Security-critical (isolation, keys, new SECURITY DEFINER functions):** prefer simple, explicit code and fail closed.

## Hard rules (as C-1c, plus)
- No secrets. Config comes from env. Tests use `@example.test` addresses only. Logs have fixed fields only: **never keys, tokens, emails or message bodies**.
- **Migrations are add-only.** `0001` to `0003` are merged: do not edit them. New files are `0004_…` onward, run as `pingzo_owner`. **Every migration states its grants explicitly.**
- **Do not edit `.github/` or `package-lock.json`.** Add **no new dependencies**. If one is truly needed, say so in the summary instead.
- **Do not weaken an existing test.** Where this file changes pinned behavior (A0), change that test's assertion as stated here, and nothing more.
- All data access stays in `withTx`, `withContext`, `withKeyContext` (or a new helper in `db.ts`), so the static-query check keeps passing.
- Code labels stay `pingzo_*` / `PINGZO_*`. In new docs the product name is Pingzoo.
- You cannot run commands. Write carefully typed code to Prettier 3.4 defaults.

## A0. C-1c known gaps closed now (migration `0004_c1d_isolation.sql`)
1. **Context narrowed to the path workspace** (KNOWN-GAPS "Context is wider than the path"). A request on `/v1/workspaces/:id/...`, or on a topic or key route, sets `app.workspace_ids` to **the path workspace intersected with the memberships `loadContext` read**: that one workspace if the caller is a member, otherwise the empty list. The helper **never adds** a workspace, so a skipped or broken permission check still sees nothing of another workspace. Add the helper in `db.ts`. Routes that must see all of the caller's workspaces (the workspace list, account deletion) keep the current context.
2. **`workspaces` SELECT scoped** (G5 round 2 SHOULD B). Replace `workspaces_select USING (true)` with: `id = ANY (<context>) OR owner_id = nullif(current_setting('app.account_id', true), '')::uuid`.
   - The two counts that cross workspaces move into SECURITY DEFINER functions: `count_owned_workspaces(account_id uuid) RETURNS integer` (used by the transfer target's cap; create may use it too) and `count_workspaces_total() RETURNS integer` (the create ceiling). Count `owner_id`, not `*`.
   - They are owned by a **new role `pingzo_counter`**: NOLOGIN, NOSUPERUSER, BYPASSRLS; its only table privilege is `SELECT (owner_id) ON workspaces` (plus USAGE on the schema); it owns only these two functions, both `STRICT STABLE`. Follow `resolve_topic_key` exactly: `SET search_path = pg_catalog, pg_temp`, schema-qualified names, `REVOKE EXECUTE … FROM PUBLIC`, `GRANT EXECUTE … TO pingzo_app`.
   - Role bootstrap: add `pingzo_counter` to `api/test/bootstrap-roles.sql` and `GRANT pingzo_counter TO pingzo_owner` there; in `global-setup.ts` the superuser step also runs `REVOKE pingzo_counter FROM pingzo_owner`. Document both in `docs/DB-ROLES.md`.
3. **Owner tied to an owner row** (ADDENDUM-1, N1). The `workspaces` UPDATE policy's `WITH CHECK` also requires `EXISTS (SELECT 1 FROM members m WHERE m.workspace_id = workspaces.id AND m.account_id = workspaces.owner_id AND m.role = 'owner')`. Transfer already promotes before it updates `owner_id`, so it keeps working.
4. **TRUNCATE** (ADDENDUM-1, N3): `pingzo_app` has no TRUNCATE on any table; add it to the privilege matrix in `00-role.test.ts`.
5. `docs/KNOWN-GAPS.md`: move the closed items into a new section "Closed at C-1d" (one line each, naming the change). No personal data.

**Tests (A0):**
- In `60-rls.test.ts`, the pinned "SELECT is open" lines now assert **404** for the broken-check GET on B.
- The 3-workspace cap and the transfer cap still work through the functions.
- `has_function_privilege('public', …)` is false for both.
- T-ROLE: `pingzo_counter` cannot log in, owns only the two functions, and `pingzo_owner` is not a member of it.
- Inside a path-workspace route, `current_setting('app.workspace_ids')` holds only that workspace (test the helper directly).
- An `UPDATE workspaces SET owner_id = <account without the owner row>` is refused, even with the context set.

## A1, A2, A8. Topics, keys, messages (migration `0005_topics_messages.sql`)
| Table | Columns and rules |
|---|---|
| `topics` | `id` uuid pk, `workspace_id` → workspaces ON DELETE CASCADE, `name` text 1–60, `last_seq` bigint not null default 0, `oldest_kept_seq` bigint not null default 1, `created_at`; **UNIQUE (id, workspace_id)**; at most `workspace_limits.max_topics` per workspace (lock the workspace row while counting) |
| `subscriptions` | `account_id` → accounts ON DELETE CASCADE, `topic_id`, `workspace_id`, `muted` boolean default false, `created_at`; pk (`account_id`, `topic_id`); **FK (`topic_id`, `workspace_id`) → topics (`id`, `workspace_id`) ON DELETE CASCADE** |
| `topic_keys` (upgrade) | add the composite FK (`topic_id`, `workspace_id`) → topics ON DELETE CASCADE with a plain `ADD CONSTRAINT` (no DELETE first: an orphan row makes the migration fail closed); add `rotated_at` timestamptz null; `expires_at` stays nullable but new keys get 365 days |
| `messages` | `id` uuid pk, `topic_id`, `workspace_id`, `seq` bigint not null, `sender_account_id` uuid null, `sender_key_id` text null, `sender_label` text not null, `sender_kind` text check in (`person`, `key`, `system`), `title` text null, `body` text not null, `created_at`; **UNIQUE (`topic_id`, `seq`)**; composite FK → topics ON DELETE CASCADE |
| `fanout_jobs` | `id` bigserial pk, `message_id` → messages ON DELETE CASCADE, `workspace_id`, `state` text default `pending` check in (`pending`, `leased`, `done`, `dead`), `attempts` int default 0, `next_at`, `lease_until` null, `created_at`. Written at publish; nothing consumes it until C-1f |

- **RLS:** ENABLE and FORCE on all five, with the template policy (identical `USING` and `WITH CHECK`).
- **Grants to `pingzo_app`:** SELECT, INSERT, UPDATE, DELETE on topics, subscriptions, topic_keys; SELECT and INSERT on messages and fanout_jobs; nothing else.
- **Routes** (all through `permissions.ts`; 404 versus 403 as in C-1c):
  - `POST /v1/workspaces/:id/topics` {name}, `GET /v1/workspaces/:id/topics`: `topic.manage` to create, `workspace.read` to list.
  - `PATCH /v1/topics/:id` {name}, `DELETE /v1/topics/:id`: `topic.manage`. A topic route finds the topic's workspace inside the caller's membership context, authorizes, then narrows the context to that workspace (A0.1).
  - `POST /v1/topics/:id/keys`: `key.manage`; at most `max_keys` keys per workspace that are unrevoked, unexpired and not rotated (`rotated_at IS NULL`); returns `pz_<id>.<secret>` **once** (secret 32 random bytes, base64url); stores only sha256(secret). `GET /v1/workspaces/:id/keys` lists ids, topic, expiry and revocation, never hashes.
  - `POST /v1/keys/:keyId/rotate`: a new key on the same topic; the old key gets `rotated_at = now()` and `expires_at = least(expires_at, now() + 24 h)`. **Rotation is allowed at the cap**, because a rotated key no longer counts; rotating a key that is already rotated, revoked or expired returns 409. `DELETE /v1/keys/:keyId`: `revoked_at = now()`, effective at once.
  - `/v1/keys/:keyId` routes find the key's workspace inside the caller's membership context, authorize, then narrow (A0.1), as topic routes do.
- **Key resolution** (PC ruling D-A): `resolve_topic_key(key_id, key_hash)` **and its contract stay unchanged**, and the hash compare stays in SQL. `withKeyContext` keeps using it. Run 2 tests keys through `withKeyContext` directly. HTTP key callers (A3) come in run 3.
- In `docs/KNOWN-GAPS.md`, close NOTE 11's "key compare" part with this reasoning: the compared value is the SHA-256 of a 256-bit random secret, so a timing leak shows at most a hash-prefix match, and using it is a preimage problem; the id lookup is covered by the 40-bit id space and the per-IP bucket (A3).

## A3, A4, A5. Publish and limits (migration `0006_publish.sql`)
| Table | Columns and rules |
|---|---|
| `rate_buckets` | `bucket` text pk (`ws:<id>` 60 a minute; `acct:<id>` and `ip:<addr>` 60 a minute each), `tokens` numeric not null, `updated_at`; token bucket refilled from `updated_at` in the same UPDATE. No RLS (counters only); `pingzo_app` SELECT, INSERT, UPDATE |
| `workspace_usage_daily` | `workspace_id`, `day` date, `count` int; pk (`workspace_id`, `day`). Debit: `INSERT … ON CONFLICT … DO UPDATE SET count = count + 1 WHERE count < limit RETURNING`. No RLS; `pingzo_app` SELECT, INSERT, UPDATE |
| `global_usage_minute` | `minute` timestamptz, `shard` smallint (0–15), `count` int; pk (`minute`, `shard`). The day's total is the sum over today's rows. No RLS; `pingzo_app` SELECT, INSERT, UPDATE |
| `idempotency_keys` | `caller` text (`a:<account_id>` or `k:<key_id>`), `key` text (1–200 printable ASCII), `workspace_id`, `message_id` uuid null, `created_at`; UNIQUE (`caller`, `key`); RLS with the template policy; `pingzo_app` SELECT, INSERT, UPDATE |
| `service_limits` (add columns) | `max_msgs_per_day_total` int default 200000, `signup_paused` boolean default false, `publish_paused_non_internal` boolean default false |

**`POST /v1/topics/:id/messages`** {title?, body} by session or key, optional `Idempotency-Key` header. A key is accepted **only** as `Authorization: Bearer pz_<8>.<secret>`; any query parameter that looks like a key is refused with 400 and never logged.
1. **Caller bucket first, in its own statement:** `ip:<addr>` for key callers (every key attempt, good or bad) or `acct:<id>` for session callers. 429 when empty.
2. **Preflight, a short transaction:** resolve the caller (key: `resolve_topic_key`; session: find the topic inside the membership context) and authorize (`message.post`; a key only on its own topic). This yields the workspace id and `kind`. A caller that is not authorized stops here with 401 or 404 and is charged **only** to its caller bucket, never to a workspace.
3. **Workspace and global debits, each in its own statement:** `ws:<id>` (60 a minute), the workspace daily counter (1,000), and for non-`dgl_internal` workspaces the global counter (503 `ceiling` at `max_msgs_per_day_total`). Each refusal is 429 (workspace) or 503 (global) and is already charged. A failed publish still counts; document it in KNOWN-GAPS.
4. **Then the main transaction:** context (member: narrowed; key: `resolve_topic_key` is the only statement before the context) → **authorize again** → `publish_paused_non_internal` blocks non-internal workspaces with 503 → body ≤ `max_body_bytes` (2,048 UTF-8 bytes; title ≤ 120) → idempotency: `INSERT … ON CONFLICT (caller, key) DO UPDATE SET workspace_id = EXCLUDED.workspace_id, message_id = NULL, created_at = now() WHERE idempotency_keys.created_at < now() - interval '24 hours' RETURNING`; if no row, `SELECT … FOR SHARE` the existing row under `lock_timeout` and return its first result (a rolled-back first attempt frees the key). If the conflicting row is not visible under the context (it belongs to another workspace), return **409 `idempotency_conflict`**, never a 500 or a retry loop → `UPDATE topics SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq` → INSERT the message → INSERT a `fanout_jobs` row → set `idempotency_keys.message_id` → `SELECT pg_notify('pingzo_msg', '<topic_id>:<seq>')` (ids only).
5. Lock wait over `lock_timeout` (3 s) returns a retryable **503 `busy`** (A7). Response 201: `{id, topic_id, seq}`.
- **Test hook** (as `skipPermissionChecks`: from `AppDeps.testHooks` only, never config): `holdAfterSeqMs` holds the transaction after it takes its `seq`, with `SET LOCAL statement_timeout = 0` and `idle_in_transaction_session_timeout = 0` on that connection only; `lockTimeoutMs` overrides `lock_timeout` for one app instance. Note both in KNOWN-GAPS (excluded from production builds later).
- **Signup and creates:** `signup_paused` makes sign-up and workspace creation return 503.
- KNOWN-GAPS: `ip:<addr>` and `acct:<id>` buckets hold personal data with no retention yet (with NOTE 15; purge at C-1g).

## A6. Disk guard, stage (a) (migration `0007_disk_guard.sql`)
- New role `pingzo_maintainer`, **test bootstrap only** (production provisioning is at C-1k; say so in `docs/DB-ROLES.md`): LOGIN, NOSUPERUSER, **NOBYPASSRLS**; grants: SELECT on `service_limits` and UPDATE (`signup_paused`, `publish_paused_non_internal`) on it, INSERT on `service_alerts` and `audit_log`, and USAGE on `audit_log_id_seq` and `service_alerts_id_seq`. **No privilege on any tenant table.** Its process arrives at C-1f; C-1d builds the logic and tests it as this role. `global-setup.ts` gives it a random password, as it does for the other login roles, and exposes its URL to the tests.
- `service_alerts`: `id` bigserial, `at`, `kind` text, `level` text check in (`warning`, `critical`), `detail` text (numbers only), `delivered_at` null (delivery is C-1h). `pingzo_app` has no access.
- `api/src/diskguard.ts`: `checkDisk(db, reading)` where `reading` is `{usedPercent}` parsed from a host status file. `PINGZO_DISK_STATUS_PATH` is **optional** in `config.ts` (CI cannot set it): unset, missing or unreadable means one alert (raised once, like the threshold alerts), never a startup failure and never a silent pass. At 80% set `signup_paused`, at 90% set `publish_paused_non_internal`, each once, each with an alert row. It never clears a flag. `clearServiceFlag(db, flag, actorId, reason)` clears one and writes `audit_log` (`action` `service.flag_clear`); there is no HTTP admin route yet. KNOWN-GAPS: the maintainer role can also clear a flag, so "only a logged admin action clears" holds by convention until the admin surface exists.

## A7. Pool budget
- api pool `max` 8; `connectionTimeoutMillis` 2000; connection options `statement_timeout=5000`, `lock_timeout=3000`, `idle_in_transaction_session_timeout=10000`. A pool timeout returns **503 `busy`** within 2 s.
- With `lock_timeout` on every connection, the existing `FOR UPDATE` calls (authorize, create, transfer, accept, deletion) can raise SQLSTATE `55P03`. Map `55P03` and the pool timeout to **503 `busy`** in one central error handler, for every route.
- Record the whole budget in `docs/DB-ROLES.md`: api 8 + 1 reserved LISTEN (C-1e), push-sender 2 and maintainer 2 (C-1f), migrations 1, admin 2: **16 in all**.

## B. Tests (all as `pingzo_app` unless a role is named)
- **T-LIMITS:** one over each of topics 3, keys 5, members 5 (unchanged), 1,000 a day, 60 a minute, body 2,048 bytes (2,048 passes, 2,049 fails; count bytes, not characters).
- **T-CEILING:** at the global ceiling, non-internal gets 503 and `dgl_internal` passes.
- **Pause flags** (run 3, flags set through `ownerPool`): `signup_paused` gives 503 on sign-up and create; `publish_paused_non_internal` gives 503 for non-internal publish and passes `dgl_internal`. Title 120 passes, 121 fails.
- **T-DISKPAUSE** (run 4, as `pingzo_maintainer`): 80% sets `signup_paused`; 90% sets `publish_paused_non_internal`; each writes one alert, once; a missing or unset path writes one alert; only `clearServiceFlag` clears, with an audit row. T-ROLE: `pingzo_maintainer` has no privilege on any tenant table.
- **T-POOL:** with the pool exhausted, a request returns 503 within 2 s.
- **T-STALL** (per-test timeout of at least 45 s, set in the test file): with `holdAfterSeqMs` 15000: (i) B (lock timeout 30 s) to T waits, then commits with `seq` A+1; (ii) with the 3 s timeout, B gets 503 `busy`, retries with the same `Idempotency-Key` after A commits, and there is exactly one B message; C to topic U and C′ to another topic in the same workspace succeed while A is held.
- **Idempotency:** a repeat returns the first result; two concurrent duplicates make one message; a rolled-back first attempt frees the key; a key older than 24 h is reused; the same caller and key in another workspace gets 409.
- **Preflight:** an unauthorized publish to a victim's topic does not debit the victim workspace's buckets or daily counter.
- **Keys** (run 2 through `withKeyContext`; run 3 over HTTP): a key works only on its topic (T-KEYCTX extended); expired and revoked keys fail at once; rotation overlap is ≤ 24 h and rotation works at the 5-key cap; the secret is shown once and only its hash is stored; a key in a query string gets 400.
- **T-RLS** extended to topics, subscriptions, topic_keys, messages, fanout_jobs and idempotency_keys (no context means no rows; context A never sees B, even through the broken-check hook).
- **T-LOGS:** no key, secret, token, email or body in any log line, including on publish and key errors.
- A `fanout_jobs` row is written per message, and `pg_notify` carries ids only.

## Out of scope
SSE and LISTEN (C-1e); fan-out, outbox, push and the worker processes (C-1f); export, purge, report, block and the transfer/deletion concurrency tests (C-1g); DGL alert delivery (C-1h); ntfy-compatible endpoint (C-2i); deployment, spend, merging.
