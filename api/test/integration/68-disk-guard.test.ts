import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import type { Pool } from "pg";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  inject,
  it,
} from "vitest";
import {
  checkDisk,
  checkDiskStatusFile,
  clearServiceFlag,
  readDiskStatus,
} from "../../src/diskguard.ts";
import { ownerPool } from "./harness.ts";

interface Flags {
  signup_paused: boolean;
  publish_paused_non_internal: boolean;
}

interface Alert {
  kind: string;
  level: string;
  detail: string;
}

// T-DISKPAUSE: the disk guard's logic, run as pingzo_maintainer. Alerts and
// flags are read, and reset, through the owner role: the maintainer cannot read
// service_alerts or audit_log, by design.
describe("T-DISKPAUSE", () => {
  const maintainer = new pg.Pool({
    connectionString: inject("maintainerUrl"),
    max: 2,
  });
  let owner: Pool;
  let dir: string;

  beforeEach(async () => {
    owner = ownerPool();
    dir = mkdtempSync(join(tmpdir(), "pingzo-disk-"));
    await reset();
  });
  afterEach(async () => {
    await reset();
    await owner.end();
    rmSync(dir, { recursive: true, force: true });
  });
  afterAll(() => maintainer.end());

  async function reset(): Promise<void> {
    await owner.query("DELETE FROM service_alerts");
    await owner.query(
      `UPDATE service_limits SET signup_paused = false,
              publish_paused_non_internal = false`,
    );
  }

  async function flags(): Promise<Flags> {
    const res = await owner.query<Flags>(
      "SELECT signup_paused, publish_paused_non_internal FROM service_limits",
    );
    return res.rows[0] as Flags;
  }

  async function alerts(): Promise<Alert[]> {
    const res = await owner.query<Alert>(
      "SELECT kind, level, detail FROM service_alerts ORDER BY id",
    );
    return res.rows;
  }

  async function auditRows(reason: string) {
    const res = await owner.query<{
      actor_account_id: string | null;
      target: string;
    }>(
      `SELECT actor_account_id, target FROM audit_log
        WHERE action = 'service.flag_clear' AND reason = $1`,
      [reason],
    );
    return res.rows;
  }

  it("runs as pingzo_maintainer", async () => {
    const res = await maintainer.query<{ u: string }>(
      "SELECT current_user AS u",
    );
    expect(res.rows[0]?.u).toBe("pingzo_maintainer");
  });

  it("does nothing below 80 percent", async () => {
    expect(await checkDisk(maintainer, { usedPercent: 79.9 })).toEqual([]);
    expect(await flags()).toEqual({
      signup_paused: false,
      publish_paused_non_internal: false,
    });
    expect(await alerts()).toEqual([]);
  });

  it("80 percent sets signup_paused with one alert, once", async () => {
    expect(await checkDisk(maintainer, { usedPercent: 80 })).toEqual([
      "disk_80",
    ]);
    expect(await flags()).toEqual({
      signup_paused: true,
      publish_paused_non_internal: false,
    });
    // A repeat, even a concurrent one, writes nothing more.
    const again = await Promise.all([
      checkDisk(maintainer, { usedPercent: 85 }),
      checkDisk(maintainer, { usedPercent: 85 }),
    ]);
    expect(again).toEqual([[], []]);
    expect(await alerts()).toEqual([
      { kind: "disk_80", level: "warning", detail: "80" },
    ]);
  });

  it("90 percent sets publish_paused_non_internal with one alert, once", async () => {
    expect(await checkDisk(maintainer, { usedPercent: 80 })).toEqual([
      "disk_80",
    ]);
    expect(await checkDisk(maintainer, { usedPercent: 92.5 })).toEqual([
      "disk_90",
    ]);
    expect(await checkDisk(maintainer, { usedPercent: 92.5 })).toEqual([]);
    expect(await flags()).toEqual({
      signup_paused: true,
      publish_paused_non_internal: true,
    });
    expect(await alerts()).toEqual([
      { kind: "disk_80", level: "warning", detail: "80" },
      { kind: "disk_90", level: "critical", detail: "92.5" },
    ]);
  });

  it("a first reading above 90 percent sets both flags", async () => {
    expect(await checkDisk(maintainer, { usedPercent: 95 })).toEqual([
      "disk_80",
      "disk_90",
    ]);
    expect(await flags()).toEqual({
      signup_paused: true,
      publish_paused_non_internal: true,
    });
    expect((await alerts()).map((a) => a.kind)).toEqual(["disk_80", "disk_90"]);
  });

  it("a missing or unset path writes one alert, once", async () => {
    expect(await checkDiskStatusFile(maintainer, null)).toEqual([
      "disk_status_missing",
    ]);
    expect(await checkDiskStatusFile(maintainer, null)).toEqual([]);
    expect(
      await checkDiskStatusFile(maintainer, join(dir, "does-not-exist.json")),
    ).toEqual([]);
    expect(await checkDisk(maintainer, null)).toEqual([]);
    expect(await alerts()).toEqual([
      { kind: "disk_status_missing", level: "warning", detail: "0" },
    ]);
    // Nothing is paused by a missing reading.
    expect(await flags()).toEqual({
      signup_paused: false,
      publish_paused_non_internal: false,
    });
  });

  it("reads the status file, and treats a bad one as missing", async () => {
    const good = join(dir, "good.json");
    writeFileSync(good, JSON.stringify({ used_percent: 83.5 }));
    expect(await readDiskStatus(good)).toEqual({ usedPercent: 83.5 });
    expect(await checkDiskStatusFile(maintainer, good)).toEqual(["disk_80"]);

    const bad = [
      ["not-json.json", "{ nope"],
      ["no-field.json", JSON.stringify({ other: 1 })],
      ["string.json", JSON.stringify({ used_percent: "83" })],
      ["over.json", JSON.stringify({ used_percent: 101 })],
      ["negative.json", JSON.stringify({ used_percent: -1 })],
    ] as const;
    for (const [name, text] of bad) {
      const path = join(dir, name);
      writeFileSync(path, text);
      expect(await readDiskStatus(path), name).toBeNull();
    }
    expect(await readDiskStatus(null)).toBeNull();
  });

  it("never clears a flag: a low reading leaves it set", async () => {
    await checkDisk(maintainer, { usedPercent: 95 });
    expect(await checkDisk(maintainer, { usedPercent: 10 })).toEqual([]);
    expect(await flags()).toEqual({
      signup_paused: true,
      publish_paused_non_internal: true,
    });
  });

  it("only clearServiceFlag clears a flag, and it writes an audit row", async () => {
    await checkDisk(maintainer, { usedPercent: 95 });
    const actor = randomUUID();
    const reason = `disk freed ${randomUUID()}`;

    expect(
      await clearServiceFlag(maintainer, "signup_paused", actor, reason),
    ).toBe(true);
    expect(await flags()).toEqual({
      signup_paused: false,
      publish_paused_non_internal: true,
    });
    expect(await auditRows(reason)).toEqual([
      { actor_account_id: actor, target: "signup_paused" },
    ]);

    // Clearing a flag that is already clear changes nothing and logs nothing.
    expect(
      await clearServiceFlag(maintainer, "signup_paused", actor, reason),
    ).toBe(false);
    expect(await auditRows(reason)).toHaveLength(1);

    // The other flag is cleared on its own, with its own audit row.
    expect(
      await clearServiceFlag(
        maintainer,
        "publish_paused_non_internal",
        actor,
        reason,
      ),
    ).toBe(true);
    expect(await flags()).toEqual({
      signup_paused: false,
      publish_paused_non_internal: false,
    });
    expect((await auditRows(reason)).map((r) => r.target).sort()).toEqual([
      "publish_paused_non_internal",
      "signup_paused",
    ]);
  });

  it("refuses a flag name it does not know", async () => {
    await expect(
      clearServiceFlag(
        maintainer,
        "max_workspaces_total" as "signup_paused",
        randomUUID(),
        "probe",
      ),
    ).rejects.toThrow("unknown service flag");
  });

  // G5 S2: row-level security on audit_log lets the maintainer add only a
  // flag-clear row with no workspace, so it cannot forge history or use up an
  // invite cap.
  it("cannot write any other audit row", async () => {
    const insert = (
      action: string,
      workspaceId: string | null,
      target: string,
    ) =>
      maintainer.query(
        `INSERT INTO audit_log (actor_account_id, workspace_id, action, target)
         VALUES ($1, $2, $3, $4)`,
        [randomUUID(), workspaceId, action, target],
      );
    await expect(insert("invite.create", randomUUID(), "x")).rejects.toThrow(
      /row-level security/,
    );
    await expect(
      insert("service.flag_clear", randomUUID(), "signup_paused"),
    ).rejects.toThrow(/row-level security/);
    await expect(
      insert("service.flag_clear", null, "max_workspaces_total"),
    ).rejects.toThrow(/row-level security/);
  });
});
