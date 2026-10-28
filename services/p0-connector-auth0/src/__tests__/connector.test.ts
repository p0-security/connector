import { afterEach, describe, expect, it, vi } from "vitest";

import { LOAD_TIMEOUT_MS } from "./fixtures.ts";

// P0's control plane imports the contract to build its typed client. It has
// no pattern to give, and shouldn't load the handlers or either cloud's
// secret-manager SDK to get it.
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

    expect(connector.roleSpec.kind).toBe("resource-root");
    expect(connector.organizationSpec.kind).toBe("resource-root");
    expect(connector.permissionSpec.kind).toBe("resource-root");
    expect(connector.Auth0ConnectorSpec).toEqual({
      role: connector.roleSpec,
      permission: connector.permissionSpec,
      organization: connector.organizationSpec,
    });
    expect(connector.installValidation.parse).toBeTypeOf("function");
    expect(connector.AUTH0_REQUIRED_SCOPES).toContain("read:users");
    expect(connector.AUTH0_TENANT_PATTERN.test("acme.auth0.com")).toBe(true);
  });
});
