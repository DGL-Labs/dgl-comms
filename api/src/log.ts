// Logs carry fixed fields only: event name, request id, route, status, latency,
// account id (uuid) and reason code. Never bodies, headers, tokens, emails or
// push tokens. The logger copies only these fields, so nothing else can leak
// through it, whatever the caller passes.

export interface LogFields {
  event: string;
  request_id?: string | null;
  route?: string | null;
  status?: number | null;
  latency_ms?: number | null;
  account_id?: string | null;
  reason?: string | null;
}

export type LogSink = (line: string) => void;

export interface Logger {
  log(fields: LogFields): void;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function stdoutSink(line: string): void {
  process.stdout.write(`${line}\n`);
}

export function createLogger(sink: LogSink = stdoutSink): Logger {
  return {
    log(fields) {
      const accountId = fields.account_id ?? null;
      sink(
        JSON.stringify({
          event: fields.event,
          request_id: fields.request_id ?? null,
          route: fields.route ?? null,
          status: fields.status ?? null,
          latency_ms: fields.latency_ms ?? null,
          account_id:
            accountId !== null && UUID.test(accountId) ? accountId : null,
          reason: fields.reason ?? null,
        }),
      );
    },
  };
}
