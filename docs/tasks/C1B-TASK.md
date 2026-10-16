# C-1b task: accounts, verification, sessions, deletion, login throttle

The builder (Claude Code Action) works from this file. Scope is C-1b only: plan C1-PLAN-r4 §8 row C-1b with ADDENDUM-1, under Taylor's C-1b go. Nothing beyond this list.

## Hard rules
- **No secrets in the repository.** Configuration comes from environment variables only, and `.env*` stays ignored. Tests use fake values.
- **The team allowlist is never committed.** It is read from env `PINGZO_TEAM_ALLOWLIST`, a comma-separated list of emails. Tests use addresses like `a@example.test` only. No real email address may appear anywhere in the repository.
- **Logs have fixed fields only:** event name, request id, route, status, latency, account id (uuid) and reason code. **Never** bodies, headers, tokens, emails or push tokens.
- **No real email provider.** Email goes through an `EmailSender` interface. The only implementation in C-1b is `TestSink`, which records messages in memory for tests.
- **Migrations are add-only.** They run as role `pingzo_owner`. The app connects as `pingzo_app`.
- **Do not edit `.github/`.** CI changes are made by C&D.

## Stack
Node 22, TypeScript (strict), Fastify, `pg`, `jose` for JWT, vitest. Prettier and ESLint use their defaults plus `@typescript-eslint`.
- Layout: `api/` for the service, `api/migrations/` for numbered SQL files, and `api/test/`.
- The migration runner is a small script that applies `NNNN_name.sql` in order and records each in `schema_migrations`.
- There is one `package.json` at the repository root, with no workspaces. It has scripts `lint` (eslint plus prettier check), `typecheck` (tsc --noEmit), `test` (unit) and `test:integration`. Dependencies use exact versions (no `^` or `~`). There are no install or postinstall scripts, since CI runs `--ignore-scripts`.
- Every dependency must be MIT, Apache-2.0, BSD-2/3-Clause or ISC.

## Data (plan §3: accounts and sessions are "as r3", so the columns come from C1-PLAN-r3 §3)
| Table | Columns |
|---|---|
| `accounts` (r3) | `id` uuid pk (random), `email` citext unique not null, `verified_at` timestamptz null, `auth_provider` text not null default `'magic_link'`, `age_attested_at` timestamptz not null, `status` text not null default `'active'`, `deleted_at` timestamptz null, `created_at` timestamptz not null default now() |
| `sessions` (r3) | `id` uuid pk, `account_id` uuid not null references accounts on delete cascade, `refresh_hash` bytea not null unique, `device_id` uuid null, `expires_at` timestamptz not null, `revoked_at` timestamptz null, `created_at` timestamptz not null default now() |
| `magic_links` (new, for A4) | `id` uuid pk, `account_id` uuid not null references accounts on delete cascade, `token_hash` bytea not null unique, `purpose` text not null (`'verify'` or `'login'`), `expires_at` timestamptz not null, `used_at` timestamptz null, `created_at` timestamptz not null default now() |
| `login_failures` (new, for A6) | `id` bigserial pk, `account_id` uuid null, `ip` inet null, `created_at` timestamptz not null default now(); indexes on (account_id, created_at) and (ip, created_at) |
| `signup_events` (new, for the cap) | `id` bigserial pk, `ip` inet not null, `created_at` timestamptz not null default now(); index on (ip, created_at) |

Notes:
- **Device column (r3).** `device_id` is r3's column. The `devices` table arrives at C-1f, so no foreign key yet.
- **Auth method.** r3 says "Magic link or argon2id, chosen at C-1b". **Chosen: magic link** (A4), so there are no passwords and no argon2.
- **Roles** (migration 0001):
  - `pingzo_owner` owns the tables;
  - `pingzo_app` is NOSUPERUSER, NOBYPASSRLS and owns nothing, with SELECT, INSERT, UPDATE and DELETE on the tables and USAGE on the sequences;
  - creating the roles themselves is done by a bootstrap SQL that the test harness runs as superuser. It is **never** used by the app.

## Behavior
1. **Sign-up.** `POST /v1/auth/signup {email, age_attested: true}`.
   - Refuse unless:
     - the email is on `PINGZO_TEAM_ALLOWLIST` (while env `PINGZO_ALLOWLIST_ON` is `true`, the default);
     - `age_attested` is true (13 or over);
     - the domain is not in `data/disposable-domains/blocklist.conf` (read at start-up);
     - fewer than 5 sign-ups came from this IP in the last 24 h.
   - Then create the account unverified and send a `verify` magic link through `EmailSender`.
   - Respond 202 with a fixed body that does not reveal whether the email exists.
2. **Magic links.** The token is 32 random bytes, base64url, sent only in the email; only its SHA-256 is stored. Links last 15 minutes and are single-use: mark `used_at` in the same statement as the check (`UPDATE … WHERE used_at IS NULL AND expires_at > now() RETURNING`). The email text is fixed.
   - `POST /v1/auth/login {email}` sends a `login` link to a verified account, and responds 202 with the same fixed body.
   - `POST /v1/auth/redeem {token}` handles both purposes:
     - for `verify`, it sets `verified_at`;
     - then it issues a session.
3. **Sessions.**
   - **Tokens.** The access token is a JWT (HS256, key from env `PINGZO_JWT_KEY`) with `sub` = account id, `sid` = session id and `exp` = 15 minutes. The refresh token is 32 random bytes; only its hash is stored, and it lasts 30 days.
   - `POST /v1/auth/refresh` rotates the token: the old refresh hash is revoked and a new one issued. Reuse of a revoked refresh token revokes all sessions of that account.
   - `POST /v1/auth/logout` revokes this session; `POST /v1/auth/logout-all` revokes all of them.
   - Every authenticated request checks that the session is not revoked and not expired.
   - Keep a `onSessionRevoked(sessionIds)` hook. Streams use it from C-1e; in C-1b it is a no-op that tests can observe.
   - Unverified accounts get 403 on everything except the auth routes.
4. **Throttle.**
   - **Counted.** Every failed redeem, or login request for an unknown or unverified address, is recorded.
   - **Backoff.** At 5 failures in 15 minutes for one account, or 20 for one IP, return 429 with `Retry-After`.
   - **Client IP.** It comes from `CF-Connecting-IP` **only** if the direct peer address is in env `PINGZO_TRUSTED_PROXIES` (CIDRs; empty by default). Otherwise the socket address is used and the header is ignored.
5. **Deletion.** `DELETE /v1/account` (authenticated) deletes the account row in one transaction, with sessions and links going by cascade, and calls `onSessionRevoked`. Afterwards the old tokens get 401. Write it as a function `deleteAccount(tx, accountId)` with a clearly marked extension point, so C-1c, C-1d and C-1f can add their own cascades.
6. **Health.** `GET /healthz` returns 200 `{ok:true}` and touches nothing secret.

## Tests (vitest; integration tests against postgres:16, connecting as `pingzo_app`)
**CI harness contract** (ci.yml is written by C&D):
- `npm run test:integration` reads env `PINGZO_TEST_SUPERUSER_URL`, a throwaway CI superuser.
- With that URL it:
  1. creates a fresh test database;
  2. runs the role bootstrap SQL;
  3. sets passwords for `pingzo_owner` and `pingzo_app` from random values generated in the test run;
  4. runs migrations as `pingzo_owner`.
- **All tests then connect as `pingzo_app`.**
- Env values for tests:
  - `PINGZO_JWT_KEY`, `PINGZO_TEAM_ALLOWLIST` (fake `@example.test` addresses) and `PINGZO_ALLOWLIST_ON` come from CI.
  - `PINGZO_TRUSTED_PROXIES` is empty in CI. Tests that need a trusted proxy set it per test.
- Unit tests (`npm test`) need no database.
- **T-ROLE** (runs first): `pingzo_app` has `rolsuper` false and `rolbypassrls` false, and owns no table.
- **T-AUTH-DENY:**
  - no token, an expired token, a revoked session and a tampered token each give 401;
  - an unverified account gets 403;
  - a non-allowlisted email is refused while the allowlist is on;
  - a domain from the blocklist is refused.
- **T-MAGIC:** a link works once; a reused, expired (clock moved past 15 minutes) or unknown link fails; the database holds only hashes.
- **T-THROTTLE:** the 6th failure in 15 minutes for one account gets 429; the 21st from one IP gets 429; `CF-Connecting-IP` from an untrusted peer is ignored.
- **T-SIGNUP-CAP:** the 6th sign-up from one IP in 24 h is refused.
- **T-DELETE-CASCADE:** after deletion, the account, its sessions and its links are gone, and its tokens get 401.
- **T-LOGS:** capture all log output during the suite, and fail if any test email, token, JWT or header value appears.
- **Unit tests:** token hashing, the IP resolver and the throttle window maths.

## Done means
All of the above is implemented, with tests written. CI (lint, typecheck, unit, integration, secrets, licenses, gitignore) is green after C&D's CI change and lockfile. **Do not** create `package-lock.json` by hand; C&D adds it from CI.
