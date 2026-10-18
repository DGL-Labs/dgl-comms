# Pingzoo message stream: the client contract (C-1e)

How a Pingzoo client receives a topic's messages live. Server-sent events are the normal path; a long-poll fallback exists
behind a flag.

## Who may connect

- Signed-in people only: `Authorization: Bearer <access token>` (the 15-minute token from sign-in or refresh).
- Topic keys are for publishing only and cannot read: a key on these routes gets 401, and a key in the query string gets
  400. Read-scoped keys are planned for C-2i.
- The caller must be a member of the topic's workspace. A topic the caller cannot see, and a topic in a suspended
  workspace, get 404.

## The stream: `GET /v1/topics/{id}/stream`

- Response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`.
- **Resume.** Send `Last-Event-ID` with the last `seq` you processed. Without it, the stream starts live and replays
  nothing. With it, the server replays up to 500 messages after that seq, in seq order, then goes live. A value that is
  not a non-negative integer gets 400.
- **Order and duplicates.** Within a stream, every message arrives once, in seq order. Across reconnects, use
  `Last-Event-ID`, and drop any seq you have already processed.
- **Keepalive.** A comment line (`: keepalive`) every 25 seconds. Treat a long silence as a dead connection and reconnect.

### Events

| Event | `id:` | `data` |
|---|---|---|
| `message` | the message's seq | `{"id", "topic_id", "seq", "title", "body", "sender_label", "sender_kind", "created_at"}` |
| `gap` | none | `{"from", "to"}`: these seqs will not be sent (purged, or more than 500 were missing). Loss is never silent. |
| `end` | none | `{"reason"}`: the server is closing this stream, see below |

A `gap` and an `end` never move your `Last-Event-ID`.

### Why a stream ends (`event: end`)

| `reason` | What the client should do |
|---|---|
| `token_expired` | The access token ran out. Refresh it, then reconnect with `Last-Event-ID`. |
| `revoked` | Access was lost: removed from the workspace, signed out, account deleted, topic deleted or workspace suspended. Do not reconnect blindly: refresh and check access first. A reconnect without access gets 401 or 404. |
| `server_closing` | The server is restarting. Reconnect with backoff and `Last-Event-ID`. |

A dropped connection with no `end` event is a network failure: reconnect with backoff and `Last-Event-ID`.

## Limits

- At most 3 open streams per session, and 2,000 per server process. Over the limit: 429 with `Retry-After: 5`.
- Long-poll requests count against the same limits.

## Long-poll fallback: `GET /v1/topics/{id}/messages?since={seq}&wait={seconds}`

- **Off unless the server sets `PINGZO_LONG_POLL=true`.** Otherwise it gets 404. It exists for networks that buffer
  server-sent events.
- `since` is required: the last seq you processed. `wait` is optional, from 0 to 25 seconds (default 25). Anything else
  gets 400.
- **The answer** is `{"messages": [...], "gaps": [...], "next": <seq>}`, with `Cache-Control: no-store`.
  - It comes back at once if anything after `since` exists; otherwise as soon as a message is published, or empty when
    `wait` runs out.
  - Call again with `since = next`.
- Same access rules, gap rule and limits as the stream.

## What the server guarantees

- **Revocation:** a stream closes within 5 seconds of a revocation. If the server's notification channel is down, it
  closes within 60 seconds, through a periodic access re-check.
- **Delivery during an outage:** if the server loses its notification channel, delivery continues by polling every 5
  seconds. After the channel returns, each topic catches up once, in order.
