# Database roles

| Role | Login | Purpose |
|---|---|---|
| `pingzo_owner` | yes | Owns the database and runs migrations. Not used by the running app. |
| `pingzo_app` | yes | The app. NOSUPERUSER, NOBYPASSRLS, and only the grants each migration gives it. |
| `pingzo_keyresolver` | no | BYPASSRLS. Owns only `resolve_topic_key`. Nobody is a member of it. |
| `pingzo_counter` | no | BYPASSRLS. Owns only `count_owned_workspaces` and `count_workspaces_total` (both `STRICT STABLE`, from migration `0004`). Its only table privilege is `SELECT (owner_id)` on `workspaces`, plus `USAGE` on the schema. Nobody is a member of it. |
| `pingzo_maintainer` | yes | The disk guard (logic in C-1d, process at C-1f). NOSUPERUSER, NOBYPASSRLS. SELECT on `service_limits` and UPDATE of `signup_paused` and `publish_paused_non_internal`; INSERT on `service_alerts` and `audit_log`; USAGE on `service_alerts_id_seq` and `audit_log_id_seq` (migration `0007`). No privilege on any tenant table (T-ROLE checks every table). **Test bootstrap only:** production provisioning is at C-1k. |

## Connection budget

Postgres connections, 16 in all:

| Use | Connections |
|---|---|
| api pool (`createPool`) | 8 |
| api reserved LISTEN (C-1e) | 1 |
| push-sender (C-1f) | 2 |
| maintainer (C-1f) | 2 |
| migrations | 1 |
| admin | 2 |

The api pool waits at most 2 seconds for a connection (`connectionTimeoutMillis`). Every api connection starts with `statement_timeout=5000`, `lock_timeout=3000` and `idle_in_transaction_session_timeout=10000` (milliseconds). A pool timeout and a lock wait over `lock_timeout` (SQLSTATE `55P03`, from the `FOR UPDATE` calls in authorize, create, transfer, accept and deletion) both return 503 `busy` with `Retry-After: 1`, from one error handler for every route. Only the publish test hooks change a timeout, for one transaction.

## Bootstrap

The production role bootstrap is created at the C-1k deploy step, from the same SQL as `api/test/bootstrap-roles.sql`. The passwords come from the deploy secret store. The bootstrap is not in the app image, and the app never runs it.

Steps, in order:

1. As a superuser: run the bootstrap SQL, then set the passwords of `pingzo_owner` and `pingzo_app` (and `pingzo_maintainer` in the test harness, which gives it a random password and exposes its URL to the tests). The bootstrap also creates `pingzo_counter` and runs `GRANT pingzo_counter TO pingzo_owner`. It creates `pingzo_maintainer` too, for the tests; production creates it at C-1k.
2. As `pingzo_owner`: run the migrations. Migration `0003` hands `resolve_topic_key` to `pingzo_keyresolver`, and migration `0004` hands the two count functions to `pingzo_counter`. Each needs `pingzo_owner` to be a member of the new owner for those statements.
3. As a superuser: `REVOKE pingzo_keyresolver FROM pingzo_owner` and `REVOKE pingzo_counter FROM pingzo_owner` (`global-setup.ts` runs both). In PostgreSQL 16 a role revokes only grants it made itself, and the bootstrap grants are the superuser's, so `0003` and `0004` cannot always do this. After this step no login role is a member of `pingzo_keyresolver` or `pingzo_counter` (T-ROLE checks `pg_auth_members`).
