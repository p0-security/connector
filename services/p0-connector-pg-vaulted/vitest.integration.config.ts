import { defineConfig } from "vitest/config";

// copy of packages/secret-manager-client/vitest.integration.config.ts
export default defineConfig({
  test: {
    include: ["src/**/*.integration.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
