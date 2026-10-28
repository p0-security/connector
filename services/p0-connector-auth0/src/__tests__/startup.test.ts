import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ALLOWED_PATTERN, LOAD_TIMEOUT_MS } from "./fixtures.ts";

// Nothing is mocked here, on purpose. The framework compiles
// `DOMAIN_ALLOW_PATTERN` itself as it loads, so these tests only pass if the
// entry points check the pattern before they load anything else, which is
// what a deployed connector does. `run.test.ts` covers the Cloud Run server,
// which has to be mocked.

vi.setConfig({ testTimeout: LOAD_TIMEOUT_MS });

beforeEach(() => {
  // Each test loads its entry point afresh, as a new process would.
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

const UNUSABLE_PATTERNS: [string, string | undefined][] = [
  ["missing", undefined],
  ["empty", ""],
  ["blank", "   "],
  ["not a regular expression", "("],
];

describe("the Lambda entry point", () => {
  it.each(UNUSABLE_PATTERNS)(
    "refuses to load when DOMAIN_ALLOW_PATTERN is %s",
    async (_case, pattern) => {
      vi.stubEnv("DOMAIN_ALLOW_PATTERN", pattern);

      await expect(import("../index.ts")).rejects.toThrow(
        "DOMAIN_ALLOW_PATTERN"
      );
    }
  );

  it("exports the handler when the pattern is usable", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

    const { handler } = await import("../index.ts");

    expect(handler).toBeTypeOf("function");
  });
});

describe("the Cloud Run entry point", () => {
  it.each(UNUSABLE_PATTERNS)(
    "refuses to start when DOMAIN_ALLOW_PATTERN is %s",
    async (_case, pattern) => {
      vi.stubEnv("DOMAIN_ALLOW_PATTERN", pattern);

      await expect(import("../run.ts")).rejects.toThrow("DOMAIN_ALLOW_PATTERN");
    }
  );
});
