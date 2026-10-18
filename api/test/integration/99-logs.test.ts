import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import {
  addMember,
  api,
  bearer,
  createWorkspace,
  makeApp,
  makeUser,
  redeem,
  registerSecret,
  signupAndVerify,
  uniqueEmail,
} from "./harness.ts";
import type { TestApp } from "./harness.ts";

const ALLOWED_FIELDS = [
  "account_id",
  "event",
  "latency_ms",
  "reason",
  "request_id",
  "route",
  "status",
];

interface LogEntry {
  route: string | null;
  status: number | null;
  reason: string | null;
}

// T-LOGS: runs last (file name order). The harness sends every app log line to
// one file for the whole suite and records every test email, token, JWT and
// header value as a secret. None may appear in the log.
describe("T-LOGS", () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await makeApp({ allowlistOn: false });
    // One more full flow, with header values of its own.
    const headerValue = `hdr-${randomBytes(12).toString("hex")}`;
    registerSecret(headerValue);
    const email = uniqueEmail();
    const tokens = await signupAndVerify(t, email);
    const extra = { "x-test-header": headerValue, "user-agent": headerValue };
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: extra,
      payload: { email },
    });
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: extra,
      payload: { email: uniqueEmail() },
    });
    const stray = randomBytes(32).toString("base64url");
    await redeem(t, stray, "198.51.100.3", extra);
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: extra,
      payload: { refresh_token: tokens.refreshToken },
    });
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      headers: extra,
      payload: { refresh_token: tokens.refreshToken },
    });
    await t.app.inject({
      method: "DELETE",
      url: "/v1/account",
      headers: { ...extra, ...bearer(tokens.accessToken) },
    });
    // A workspace and an invitation: the invitee's email and the invite token
    // must stay out of the log too.
    const host = await makeUser(t);
    const guest = await makeUser(t);
    const workspaceId = await createWorkspace(t, host, "Log probe");
    await addMember(t, host, workspaceId, guest);
    await api(
      t,
      guest,
      "DELETE",
      `/v1/workspaces/${workspaceId}/members/${guest.accountId}`,
    );
    // Publish and key errors: a topic, a key, and requests that fail in each
    // way. The key, its secret, a wrong secret and the message body must stay
    // out of the log.
    const topic = await api(
      t,
      host,
      "POST",
      `/v1/workspaces/${workspaceId}/topics`,
      { name: "Probe" },
    );
    const topicId = topic.json<{ id: string }>().id;
    const made = await api(t, host, "POST", `/v1/topics/${topicId}/keys`);
    const { id: keyId, key } = made.json<{ id: string; key: string }>();
    registerSecret(key);
    registerSecret(key.slice(key.indexOf(".") + 1));
    registerSecret(keyId);
    const wrongKey = `${keyId}.${randomBytes(32).toString("base64url")}`;
    registerSecret(wrongKey);
    registerSecret(wrongKey.slice(wrongKey.indexOf(".") + 1));
    const probeBody = `body-${randomBytes(12).toString("hex")}`;
    registerSecret(probeBody);
    const publishUrl = `/v1/topics/${topicId}/messages`;
    const byKey = (credential: string) =>
      t.app.inject({
        method: "POST",
        url: publishUrl,
        remoteAddress: "203.0.113.77",
        headers: { authorization: `Bearer ${credential}` },
        payload: { body: probeBody },
      });
    await byKey(key);
    await byKey(wrongKey);
    await t.app.inject({
      method: "POST",
      url: `${publishUrl}?key=${encodeURIComponent(key)}`,
      headers: bearer(host.accessToken),
      payload: { body: probeBody },
    });
    await api(t, host, "POST", publishUrl, {
      body: `${probeBody}${"x".repeat(2100)}`,
    });
    await api(t, host, "DELETE", `/v1/keys/${keyId}`);
    await byKey(key);
    await api(t, host, "POST", `/v1/keys/${keyId}/rotate`);
    await t.app.inject({ method: "GET", url: "/healthz", headers: extra });
    await t.app.inject({
      method: "POST",
      url: "/v1/auth/signup",
      headers: { ...extra, "content-type": "application/json" },
      payload: "{ not json",
    });
  });
  afterAll(() => t.close());

  it("logs requests, with fixed fields only", () => {
    const lines = readFileSync(inject("logFile"), "utf8")
      .split("\n")
      .filter((line) => line !== "");
    expect(lines.length).toBeGreaterThan(5);
    for (const line of lines) {
      const entry = JSON.parse(line) as Record<string, unknown>;
      expect(Object.keys(entry).sort()).toEqual(ALLOWED_FIELDS);
    }
  });

  it("logs publish and key errors by route, status and reason only", () => {
    const entries = readFileSync(inject("logFile"), "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as LogEntry);
    const statuses = (route: string) =>
      new Set(entries.filter((e) => e.route === route).map((e) => e.status));
    const published = statuses("/v1/topics/:id/messages");
    for (const status of [201, 400, 401, 413]) {
      expect(published.has(status), `publish ${status}`).toBe(true);
    }
    expect(statuses("/v1/keys/:keyId/rotate").has(409)).toBe(true);
    expect(entries.some((e) => e.reason === "key_in_query")).toBe(true);
  });

  it("never contains a test email, token, JWT or header value", () => {
    const log = readFileSync(inject("logFile"), "utf8");
    const secrets = readFileSync(inject("secretsFile"), "utf8")
      .split("\n")
      .filter((value) => value !== "");
    // The suite must have recorded a meaningful number of values.
    expect(secrets.length).toBeGreaterThan(5);
    for (const secret of secrets) {
      expect(log.includes(secret)).toBe(false);
    }
    expect(log).not.toContain("example.test");
    expect(log.toLowerCase()).not.toContain("bearer");
  });
});
