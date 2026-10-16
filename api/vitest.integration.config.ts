import { defineConfig } from "vitest/config";

// Integration tests: postgres:16, connecting as pingzo_app. Files share one
// database, so they run one after another, in file-name order (00-role first).
export default defineConfig({
  test: {
    include: ["api/test/integration/**/*.test.ts"],
    globalSetup: ["api/test/integration/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 60000,
  },
});
