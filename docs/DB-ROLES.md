# Database roles

| Role | Login | Purpose |
|---|---|---|
| `pingzo_owner` | yes | Owns the database and runs migrations. Not used by the running app. |
| `pingzo_app` | yes | The app. NOSUPERUSER, NOBYPASSRLS, and only the grants each migration gives it. |
| `pingzo_keyresolver` | no | BYPASSRLS. Owns only `resolve_topic_key`. Nobody is a member of it. |
| `pingzo_counter` | no | BYPASSRLS. Owns only `count_owned_workspaces` and `count_workspaces_total` (both `STRICT STABLE`, from migration `0004`). Its only table privilege is `SELECT (owner_id)` on `workspaces`, plus `USAGE` on the schema. Nobody is a member of it. |

## Bootstrap

The production role bootstrap is created at the C-1k deploy step, from the same SQL as `api/test/bootstrap-roles.sql`. The passwords come from the deploy secret store. The bootstrap is not in the app image, and the app never runs it.

Steps, in order:

1. As a superuser: run the bootstrap SQL, then set the passwords of `pingzo_owner` and `pingzo_app`. The bootstrap also creates `pingzo_counter` and runs `GRANT pingzo_counter TO pingzo_owner`.
2. As `pingzo_owner`: run the migrations. Migration `0003` hands `resolve_topic_key` to `pingzo_keyresolver`, and migration `0004` hands the two count functions to `pingzo_counter`. Each needs `pingzo_owner` to be a member of the new owner for those statements.
3. As a superuser: `REVOKE pingzo_keyresolver FROM pingzo_owner` and `REVOKE pingzo_counter FROM pingzo_owner` (`global-setup.ts` runs both). In PostgreSQL 16 a role revokes only grants it made itself, and the bootstrap grants are the superuser's, so `0003` and `0004` cannot always do this. After this step no login role is a member of `pingzo_keyresolver` or `pingzo_counter` (T-ROLE checks `pg_auth_members`).
