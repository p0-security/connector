import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    retry: 2,
    include: ["**/*.{test,spec}.?(c|m)[jt]s?(x)"],
    exclude: ["**/node_modules/**", "**/dist/**", "**/*.integration.test.ts"],
  },
});
