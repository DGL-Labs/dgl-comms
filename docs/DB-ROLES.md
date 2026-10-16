# Database roles

| Role | Login | Purpose |
|---|---|---|
| `pingzo_owner` | yes | Owns the database and runs migrations. Not used by the running app. |
| `pingzo_app` | yes | The app. NOSUPERUSER, NOBYPASSRLS, and only the grants each migration gives it. |
| `pingzo_keyresolver` | no | BYPASSRLS. Owns only `resolve_topic_key`. Nobody is a member of it. |

## Bootstrap

The production role bootstrap is created at the C-1k deploy step, from the same SQL as `api/test/bootstrap-roles.sql`. The passwords come from the deploy secret store. The bootstrap is not in the app image, and the app never runs it.

Steps, in order:

1. As a superuser: run the bootstrap SQL, then set the passwords of `pingzo_owner` and `pingzo_app`.
2. As `pingzo_owner`: run the migrations. Migration `0003` hands `resolve_topic_key` to `pingzo_keyresolver`, which needs `pingzo_owner` to be a member of it for that one statement.
3. As a superuser: `REVOKE pingzo_keyresolver FROM pingzo_owner`. In PostgreSQL 16 a role revokes only grants it made itself, and the bootstrap grant is the superuser's, so `0003` cannot always do this. After this step no login role is a member of `pingzo_keyresolver` (T-ROLE checks `pg_auth_members`).
