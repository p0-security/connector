import type * as connectorModule from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ALLOWED_PATTERN, LOAD_TIMEOUT_MS } from "./fixtures.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const runCloudRunConnector = vi.hoisted(() => vi.fn());

// The Cloud Run entry point starts a server as it loads.
vi.mock("@p0security/connector", async (importOriginal) => ({
  ...(await importOriginal<typeof connectorModule>()),
  runCloudRunConnector,
}));

vi.setConfig({ testTimeout: LOAD_TIMEOUT_MS });

beforeEach(() => {
  // Each test loads the entry point afresh, as a new process would.
  vi.resetModules();
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("the Cloud Run entry point", () => {
  it("starts the server when the pattern is usable", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

    await import("../run.ts");

    expect(runCloudRunConnector).toHaveBeenCalledTimes(1);
    expect(runCloudRunConnector).toHaveBeenCalledWith(
      "P0 ClickHouse Cloud connector",
      expect.anything(),
      expect.any(Function)
    );
  });

  // Every procedure logs through the logger in its context.
  it("gives each request a context with a logger", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

    await import("../run.ts");
    const [, , createContext] = runCloudRunConnector.mock.calls[0] ?? [];

    await expect(createContext()).resolves.toEqual({
      logger: expect.objectContaining({ info: expect.any(Function) }),
    });
  });

  it("doesn't start the server when the pattern is unusable", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", "(");

    await expect(import("../run.ts")).rejects.toThrow("DOMAIN_ALLOW_PATTERN");
    expect(runCloudRunConnector).not.toHaveBeenCalled();
  });
});
