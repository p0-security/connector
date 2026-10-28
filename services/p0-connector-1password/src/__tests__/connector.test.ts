import { afterEach, describe, expect, it, vi } from "vitest";

import { LOAD_TIMEOUT_MS } from "./fixtures.ts";

// P0's control plane imports the contract to build its typed client. It has
// no pattern to give, and shouldn't load the handlers or either cloud's
// secret-manager SDK, or the 1Password SDK, to get it.
vi.mock("../router.ts", () => {
  throw new Error("the control plane's entry point loaded the router");
});

vi.setConfig({ testTimeout: LOAD_TIMEOUT_MS });

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("the control plane's entry point", () => {
  it("loads the contract without the router, and without DOMAIN_ALLOW_PATTERN", async () => {
    vi.stubEnv("DOMAIN_ALLOW_PATTERN", undefined);

    const connector = await import("../connector.ts");

    expect(connector.shareSpec.kind).toBe("resource-root");
    expect(connector.OnePasswordConnectorSpec).toEqual({
      share: connector.shareSpec,
    });
    expect(connector.installValidation.parse).toBeTypeOf("function");
  });
});
