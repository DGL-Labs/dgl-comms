import { describe, expect, it } from "vitest";
import {
  ACCOUNT_LIMIT,
  IP_LIMIT,
  WINDOW_MS,
  retryAfterSeconds,
} from "../../src/throttle.ts";

const NOW = 1_000_000_000_000;

function failuresAt(count: number, ageMs: number): number[] {
  return Array.from({ length: count }, () => NOW - ageMs);
}

describe("retryAfterSeconds", () => {
  it("allows fewer failures than the limit", () => {
    expect(retryAfterSeconds(failuresAt(4, 1000), NOW, ACCOUNT_LIMIT)).toBe(0);
    expect(retryAfterSeconds(failuresAt(19, 1000), NOW, IP_LIMIT)).toBe(0);
  });

  it("blocks at the limit and says when the oldest failure ages out", () => {
    const times = failuresAt(5, 60_000);
    expect(retryAfterSeconds(times, NOW, ACCOUNT_LIMIT)).toBe(
      (WINDOW_MS - 60_000) / 1000,
    );
    expect(retryAfterSeconds(failuresAt(20, 0), NOW, IP_LIMIT)).toBe(
      WINDOW_MS / 1000,
    );
  });

  it("ignores failures outside the window", () => {
    const old = failuresAt(5, WINDOW_MS);
    expect(retryAfterSeconds(old, NOW, ACCOUNT_LIMIT)).toBe(0);
    const mixed = [...failuresAt(3, WINDOW_MS + 1), ...failuresAt(4, 10)];
    expect(retryAfterSeconds(mixed, NOW, ACCOUNT_LIMIT)).toBe(0);
  });

  it("waits only until enough failures age out", () => {
    // 7 failures, limit 5: blocked until the 3rd-oldest leaves the window.
    const times = [
      NOW - 800_000,
      NOW - 700_000,
      NOW - 600_000,
      NOW - 500_000,
      NOW - 400_000,
      NOW - 300_000,
      NOW - 200_000,
    ];
    expect(retryAfterSeconds(times, NOW, 5)).toBe(
      Math.ceil((WINDOW_MS - 600_000) / 1000),
    );
  });

  it("never returns less than one second when blocked", () => {
    const times = failuresAt(5, WINDOW_MS - 1);
    expect(retryAfterSeconds(times, NOW, ACCOUNT_LIMIT)).toBe(1);
  });
});
