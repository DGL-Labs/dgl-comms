# C-1e task: SSE stream, LISTEN/NOTIFY, resume, gap event (r2)

r2: PC ruling 2026-10-18 on the PD's question: topic keys do not stream in C-1e (B1, T). Nothing else changed from r1.

The builder (Claude Code Action) works from this file. Scope is C-1e only: C1-PLAN-r4 section 8 row C-1e ("SSE stream, LISTEN/NOTIFY, resume, gap event"; also section 2 "SSE stream", section 6, MUST 3, MUST 4, and the revocation and gap SHOULDs), with C1-PLAN-r4-ADDENDUM-1 SHOULD 4, carried by C1E-TASK-LIST-r2 under Taylor's C-1e go. PC rulings D1 (T-SSE-CF deferred to C-1l) and D2 (the load job runs inside the existing integration job) apply. The work is split into three runs; each run's comment names its sections. **Security-critical (access, RLS, the LISTEN hint, revocation):** prefer simple, explicit code and fail closed.

## Hard rules (as C-1d, plus)
- No secrets. Config comes from env. Tests use `@example.test` addresses only. Logs have fixed fields only: **never keys, tokens, emails or message bodies**.
- **Migrations are add-only.** `0001` to `0007` are merged: do not edit them. A new migration, if a run needs one, is `0008_…` onward, run as `pingzo_owner`, and states its grants explicitly. Run 1 needs none (`topics.oldest_kept_seq` exists).
- **Do not edit `.github/` or `package-lock.json`.** Add **no new dependencies**: SSE is written with Fastify's `reply.hijack()` and `reply.raw`, LISTEN with `pg`. If one is truly needed, say so in the summary instead.
- **Do not weaken an existing test.**
- All data access stays in `withTx`, `withContext`, `withKeyContext`, `withPathContext` or a new helper in `db.ts`. **The LISTEN client is created in `db.ts`** (the static-query test allows a direct client only there).
- **A stream never holds a transaction or a pooled connection while it is open.** The access check, the replay read and each live row read are short transactions that end before the stream waits. The only long-lived connection is the one LISTEN client per process (C-1d A7 budget: api 8 + 1 reserved LISTEN).
- Code labels stay `pingzo_*` / `PINGZO_*`. In new docs the product name is Pingzoo.
- You cannot run commands. Write carefully typed code to Prettier 3.4 defaults.

## B1. Stream endpoint (run 1)
`GET /v1/topics/:id/stream`, server-sent events.
- **Callers: signed-in people only** (a 15-minute access token, `Authorization: Bearer <JWT>`). **Topic keys do not stream in C-1e** (PC ruling, 2026-10-18): C1-PLAN-r4 makes topic keys publish-only, and a stream replays up to 500 past messages, so a leaked publish key would expose the topic's history. A topic key presented on the stream route gets **401** before anything else happens: it is never resolved, no database call is made for it, and no stream is registered. A key in the query string gets 400, as for publish. Read-scoped keys are C-2i, with G-1 as a separate read scope.
- **Access:** the caller needs membership of the topic's workspace (`workspace.read`), checked with `inFoundWorkspace` (find in memberships, authorize, then narrow). A topic the caller cannot see is 404, as for other topic routes.
- **Opening order (MUST 3).** In this order:
  1. check access (a short transaction; it returns the topic's workspace id);
  2. **register** the stream in the in-process topic map, buffering live events from now on;
  3. **replay** `seq > Last-Event-ID` (at most 500, in seq order; a short transaction under the same RLS context as step 1);
  4. send the replay;
  5. flush the buffer, **dropping any seq already sent**;
  6. go live.
- **`Last-Event-ID`:** from the request header. Absent means live only (no replay). Present, it must be a non-negative integer, otherwise 400.
- **Event format:** `id: <seq>`, `event: message`, `data: <JSON>` with `id`, `topic_id`, `seq`, `title`, `body`, `sender_label`, `sender_kind`, `created_at`. Each event's `id:` is its `seq`.
- **Headers:** `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`.
- **Keepalive:** a comment line (`: keepalive`) every 25 s. The interval comes from `AppDeps.testHooks` in tests only.
- **Limits:** at most 3 open streams per session and 2,000 per process; above that, 429 before anything is registered. The per-process cap comes from `AppDeps.testHooks` in tests only.
- **Close:** a client disconnect removes the stream from the map at once. `app.close()` ends every stream and closes the LISTEN client.
- **Logs:** one line when a stream opens and one when it ends (route, status, reason). Never a body, title, token or key.

## B2. LISTEN (run 1)
- One **direct** LISTEN client per api process, on `pingzo_msg`, created in `db.ts`. It uses `PINGZO_LISTEN_URL` if set (optional in `config.ts`; production points it past any pooler), otherwise the database URL. It is started with the app and closed by `app.close()`.
- **The payload is a hint only (G5 C-1d N7).** `publish.ts` sends `<topic_id>:<seq>`. On a notify:
  - if no stream is registered for that topic, do nothing;
  - otherwise load the row **once**, as `pingzo_app`, in a short transaction whose RLS context is **the workspace recorded on the registered stream at access time** (a new `db.ts` helper that sets `app.workspace_ids` to that one workspace with `SET LOCAL`). **Never take a workspace from the payload.**
  - if the row is not found or not visible, drop it;
  - write it to that topic's open streams, through the same per-stream "drop any seq already sent" rule.
- A malformed payload is dropped and logged as `reason: bad_notify` (no payload in the log).

## B3. Gap event (run 1)
Loss is never silent. On opening (and wherever a replay happens later):
- If `Last-Event-ID` is below the topic's `oldest_kept_seq - 1`, send `event: gap` with `data: {"from": Last-Event-ID + 1, "to": oldest_kept_seq - 1}`, then replay from `oldest_kept_seq`.
- If more than 500 messages are missing, send `event: gap` for the part that will not be replayed (`from` = Last-Event-ID + 1, `to` = last_seq - 500), then replay the newest 500.
- A gap event has no `id:` line, so it does not move the client's `Last-Event-ID`.

## B4. LISTEN outage (MUST 4) (run 2)
- Every open stream polls `seq > its own last sent` every 5 s while LISTEN is down (or always, if simpler and within the pool budget; say which).
- The LISTEN client reconnects with backoff. After it reconnects, each stream replays once from its own last seq, then goes live.

## B5. Revocation (SHOULD) (run 2)
`NOTIFY pingzo_acl` (ids only) closes the affected streams within 5 s, or within 60 s at worst through a per-stream re-check of access. It fires on: member removal or a role change; session revoke; account deletion; topic delete; workspace suspension; key revoke. A stream also ends when its 15-minute access token expires.

## B6. Long-poll fallback (run 3)
Behind a flag that is off by default (ADDENDUM-1 SHOULD 4). `GET /v1/topics/:id/messages?since=<seq>` with a bounded wait. Same access, same RLS path, same gap rule, same limits. It is built in all cases, so a later Cloudflare buffering finding does not change the architecture.

## B7. Docs (run 3)
- `docs/STREAM.md`: the client contract (resume, gap, keepalive, 429, token refresh).
- `docs/KNOWN-GAPS.md`: a C-1e section, with no personal data. It must say: "T-SSE-CF (Cloudflare buffering) is deferred to C-1l, on the real deployment (PC ruling D1). C-1e proves SSE locally and in CI. The long-poll fallback (B6) is built behind a flag in case Cloudflare buffers the stream."

## T. Tests (all as `pingzo_app`; streams are read over a real socket: listen on port 0 and use `node:http`, since `inject` does not stream)
Run 1:
- **Opening order:** a publish during the replay is delivered exactly once, in seq order.
- **T-STALL (stream part):** with `holdAfterSeqMs` 15000, publish A to T is held and B waits; a stream on T gets A, then B, with no gap; a stream on topic U is not delayed. Per-test timeout at least 45 s, set in the test file.
- **Gap event:** a forced `oldest_kept_seq` (set through `ownerPool`) above `Last-Event-ID` gives `event: gap` with the right `from` and `to`; so does a 501-message gap.
- **N7 hint test:** a forged `pg_notify('pingzo_msg', …)` naming another workspace's topic, or a missing row, delivers nothing to any stream.
- **Limits:** the 4th stream on one session gets 429; the per-process cap (test setting) gives 429; keepalive arrives on time (test setting); the headers are present; a bad `Last-Event-ID` gets 400.
- **Cross-workspace deny:** a member of workspace X cannot open a stream on workspace Y's topic (404).
- **Keys refused:** a valid topic key for T, presented on `GET /v1/topics/T/stream`, gets 401 and registers no stream; so does a key for another topic; a key in the query string gets 400.
- **Pool:** an open stream holds no pooled connection (for example, open 9 streams across three callers and show that a normal request still succeeds with the 8-connection pool).
- **T-LOGS:** extend it to cover stream open, end and refusal. No token, key, email or body appears.

Run 2: **T-LISTEN** (LISTEN killed in the middle of a burst; every seq still arrives exactly once); **revocation** (each of the 6 triggers closes the stream within 5 s with LISTEN up; with LISTEN down, within 60 s, a test setting may shorten the re-check); token expiry ends a stream.

Run 3: long-poll (same access, gap and limits; off by default); the **load job** (plan section 6): 50 SSE clients and 10 publishes a second for 60 s, with one 15 s stalled commit and one LISTEN kill; every seq arrives exactly once with no gap. It runs **inside the existing integration job** (PC ruling D2): no `.github/` edit, no new CI job. The summary reports the integration job's duration before and after.

CI: all jobs green after each run.

## Out of scope
Fan-out worker, outbox and push (C-1f); retention purge and T-PURGE (C-1g; the gap event is tested here with a forced `oldest_kept_seq`); DGL alert kinds (C-1h); deployment; T-SSE-CF (deferred to C-1l, PC ruling D1); any Cloudflare resource, tunnel or sse-test environment; merging.
