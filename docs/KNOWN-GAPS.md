# Known gaps

## C-1b (G5 round 1)

These are accepted for C-1b (G5 round 1). Each has a later task that closes it.

### Timing (SHOULD 3)

`POST /v1/auth/login` gives the same 202 body for known and unknown addresses, but the two paths differ in timing: a known address makes a link and sends an email, an unknown one does not. The send moves to the outbox and worker at C-1f, which removes the difference.

### IPv6 (SHOULD 9)

The sign-up cap and the login and redeem limits count per single IP address. An IPv6 client can rotate through the addresses of its /64 and avoid them. Grouping by /64 comes at C-1g.

### Retention (NOTE 15)

Nothing purges expired `magic_links` and `sessions` yet, nor `signup_events` and `login_failures`, which hold IP addresses (personal data). A retention job comes at C-1g, and the privacy policy must cover these records and how long they are kept.

### Allowlist (NOTE 16)

Sign-up answers 403 for an address that is not on the team allowlist and 202 for one that is, so the status code reveals allowlist membership. This is accepted for the closed alpha, until C-2.

### JWT key (SHOULD 7)

`PINGZO_JWT_KEY` must be random, at least 256 bits, and provided at deploy. The 32-character check in the config loader is a length check, not an entropy check, and does not catch a weak key.

## C-1b (G5 round 2)

1. Link exhaustion: any IP can use up an account's 3 login links per 15 minutes, which voids the pending link. Re-sending sign-up voids an unverified account's verify link, limited only by the per-IP cap. Fix candidate in C-1g: exempt the most recent link from voiding, or a per-account cap plus a cool-off.
2. Shared IP budget: login and redeem share 20 per IP per 15 minutes, so users behind one NAT can lock each other out, and `login_failures` grows by one row per login. Fix candidates in C-1g: separate budgets, IPv6 /64 grouping, retention.
3. Sign-up timing: sign-up for an existing verified email skips the send. This adds to the login timing gap.
4. `PINGZO_JWT_KID` defaults to `k1`. The deploy step (C-1k) must set it deliberately when the key is rotated.
5. Row-level security was not in C-1b. It arrives in C-1c.
6. Default table privileges are unchanged. Each new migration states its grants.

## C-1c

Accepted for C-1c (G5 round 1). Each has a later step that closes it.

### `withTx` is still allowed (NOTE 8)

`withTx` (no context) remains available. It is safe only for tables with RLS. Writes to `workspaces` and `audit_log` must go through `withContext`.

### `skipPermissionChecks` (NOTE 9)

The `skipPermissionChecks` hook comes only from `deps` and is a test hook. It is to be excluded from production builds later.

### Schema name and key compare (NOTE 11)

The schema is `public.`, not ADD-1's `pingzo.`. `resolve_topic_key` compares the key hash with `=` inside the function. That is acceptable because the hash is a SHA-256 of a random secret, but ADD-1's constant-time compare in the app is not done.

### Invites and suspended workspaces (NOTE 12)

Invite emails are not checked against the domain blocklist, and actions on suspended workspaces are still allowed. Both come at a later step.

### Role bootstrap membership

In PostgreSQL 16, `pingzo_owner` cannot revoke its own membership of `pingzo_keyresolver` (and, from C-1d, `pingzo_counter`), because the superuser made the grant. The superuser step in the role bootstrap does it after the migrations (see `docs/DB-ROLES.md`).

### Production role check (G5 round 2, N2)

The T-ROLE check that no app role is a member of `pingzo_keyresolver` proves only the test bootstrap. C-1k adds the same fail-fast check at startup that `global-setup.ts` does. A later migration that alters `resolve_topic_key` needs the bootstrap's membership grant again.

### Tables without RLS (G5 round 2, N3)

`workspace_limits` and `audit_log` have no row-level security and are readable across workspaces (numbers and ids only).

### No concurrency tests (G5 round 2, N4)

No test races two transfers against the target's cap, or account deletion against a transfer. Their serialization (the account row lock, then workspaces) comes from reading the code, not from a test.

## C-1d (publish, limits, disk guard and pool)

Accepted for C-1d. Each has a later step that closes it.

### A failed publish still counts

The workspace bucket, the workspace daily counter and the global counter are debited, each in its own statement, before the main transaction runs. If the main transaction then fails (a body that is too large, a 503 `busy`, an idempotency conflict, a pause flag), the debit stays. A client that retries a refused publish uses up its allowance faster. This is intended: a refused or failed attempt costs the service something, and a debit that could be undone would need the debit and the publish in one transaction, which would hold a counter row lock for the whole publish.

The global ceiling is checked and counted in one statement, but writers on different shards do not wait on each other, so the day's total can pass `max_msgs_per_day_total` by about the number of publishes in flight at once.

### Test hooks (`holdAfterSeqMs`, `lockTimeoutMs`)

`AppDeps.testHooks.holdAfterSeqMs` holds a publish transaction after it takes its `seq`, with `statement_timeout` and `idle_in_transaction_session_timeout` off on that connection only. `AppDeps.testHooks.lockTimeoutMs` overrides `lock_timeout` for one app instance (and sets `statement_timeout` 5 seconds above it, so that the wait is not cut short). Both come from `deps` only, never from config or the environment, like `skipPermissionChecks` (NOTE 9). They are to be excluded from production builds later.

### Bucket retention (with NOTE 15)

`rate_buckets` rows named `ip:<address>` and `acct:<account id>` hold personal data and have no retention yet. Nothing purges them, nor the `ws:` rows, `workspace_usage_daily`, `global_usage_minute` or `idempotency_keys`. The purge comes at C-1g, together with the other retention jobs in NOTE 15, and the privacy policy must cover these records.

### Publish details

- A session caller is charged to its `acct:` bucket after its session check, so a request with no valid session is charged to nothing. Only key callers are charged to an `ip:` bucket first.
- The publish permission check (`message.post`) does not lock the workspace row, unlike `authorize` for other actions, so publishes to different topics of one workspace do not wait on each other. A membership change that commits between the preflight and the main transaction is seen by the second check; one that commits after it is not.
- A person's message has the sender label `Member` for now. The sender account id is stored; a display name comes with the clients.
- A committed idempotency row whose message has since been deleted (a topic deleted with its messages) answers 409 `idempotency_conflict` until the row is 24 hours old.

### Flag clearing is admin by convention (A6)

`clearServiceFlag` is the only code that clears `signup_paused` or `publish_paused_non_internal`, and it writes an `audit_log` row (`service.flag_clear`). There is no HTTP admin route yet, and the `pingzo_maintainer` role can also `UPDATE` those two columns directly, so "only a logged admin action clears a flag" holds by convention until the admin surface exists. The role is test bootstrap only; production provisioning is at C-1k.

### Disk guard (A6)

- Only stage (a) is built: the check logic and its tests. Nothing calls it yet; its process arrives at C-1f, and alert delivery at C-1h (`service_alerts.delivered_at` stays null).
- The host status file is JSON, `{"used_percent": 83.5}`. `PINGZO_DISK_STATUS_PATH` is optional; unset, missing, unreadable or malformed gives one `disk_status_missing` alert and never a startup failure.
- An alert is raised when its flag flips from clear to set. After an admin clears a flag, the next reading at or over the threshold raises the alert again.

### Busy mapping (A7)

Only SQLSTATE `55P03` and the pool's connection timeout map to 503 `busy`. A `statement_timeout` (`57014`) is still a 500.

## Closed at C-1d

- Context is wider than the path (NOTE 7): `withPathContext` in `db.ts` sets the context to the path workspace intersected with the caller's memberships; it never adds one.
- Workspaces SELECT is open (G5 round 2, SHOULD B): migration `0004` scopes the policy to the context or `owner_id` = the caller, and the two cross-workspace counts moved into the SECURITY DEFINER functions `count_owned_workspaces` and `count_workspaces_total`, owned by `pingzo_counter`.
- Owner not tied to an owner member row (G5 round 2, N1): migration `0004` adds the owner-row `EXISTS` to the `workspaces` UPDATE policy's `WITH CHECK`.
- `TRUNCATE` missing from the privilege matrix (G5 round 2, N3): `00-role.test.ts` now checks that `pingzo_app` has no `TRUNCATE` on any table.
- Key compare (NOTE 11, the compare part): `resolve_topic_key` keeps its `=` on the hash inside SQL, and the app does no constant-time compare. The compared value is the SHA-256 of a 256-bit random secret, so a timing leak shows at most a match of a hash prefix, and using that is a preimage problem. The id lookup is covered by the 40-bit id space and the per-IP bucket (A3, run 3). The schema name (`public.`, not `pingzo.`) is still as noted above.
