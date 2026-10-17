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

## Closed at C-1d

- Context is wider than the path (NOTE 7): `withPathContext` in `db.ts` sets the context to the path workspace intersected with the caller's memberships; it never adds one.
- Workspaces SELECT is open (G5 round 2, SHOULD B): migration `0004` scopes the policy to the context or `owner_id` = the caller, and the two cross-workspace counts moved into the SECURITY DEFINER functions `count_owned_workspaces` and `count_workspaces_total`, owned by `pingzo_counter`.
- Owner not tied to an owner member row (G5 round 2, N1): migration `0004` adds the owner-row `EXISTS` to the `workspaces` UPDATE policy's `WITH CHECK`.
- `TRUNCATE` missing from the privilege matrix (G5 round 2, N3): `00-role.test.ts` now checks that `pingzo_app` has no `TRUNCATE` on any table.
