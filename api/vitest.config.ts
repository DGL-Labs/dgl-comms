import { defineConfig } from "vitest/config";

// Unit tests: no database.
export default defineConfig({
  test: {
    include: ["api/test/unit/**/*.test.ts"],
  },
});
