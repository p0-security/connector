import { describe, expect, it } from "vitest";

import {
  type ConnectorPrimitives,
  connectorParsers,
  createLogger,
  newConnectorTRPC,
  newCustomConnectorRouter,
  newResourceRootRouter,
} from "../index.ts";

describe("the pre-instantiated resource-root router", () => {
  const primitives: ConnectorPrimitives = {
    validation: () => ({ user: null }),
    getUser: async () => null,
    createUser: async (_context, userBody) => `user:${userBody.principal}`,
    deleteUser: async () => {},
    setPoliciesForUser: async () => {},
    list: async () => [{ key: "policy-1", value: "Policy 1" }],
  };

  it("builds a router exposing exactly the five resource-root procedures", () => {
    const t = newConnectorTRPC();
    const router = newResourceRootRouter(t, connectorParsers, () => primitives);

    expect(Object.keys(router._def.procedures).sort()).toEqual(
      [
        "deleteUser",
        "identifyUser",
        "list",
        "provisionUser",
        "setPoliciesForUser",
      ].sort()
    );
  });

  it("provisions a user through the built router's caller", async () => {
    const t = newConnectorTRPC();
    const router = newResourceRootRouter(t, connectorParsers, () => primitives);
    const caller = t.createCallerFactory(router)({ logger: createLogger() });

    const userId = await caller.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });

    expect(userId).toBe("user:person@example.com");
  });
});

/**
 * `newCustomConnectorRouter` is what a real connector actually calls; the
 * suite above only proves the pieces it assembles fit together.
 */
describe("newCustomConnectorRouter", () => {
  const primitives: ConnectorPrimitives = {
    validation: () => ({ user: null }),
    getUser: async () => null,
    createUser: async (_context, userBody) => `user:${userBody.principal}`,
    deleteUser: async () => {},
    setPoliciesForUser: async () => {},
    list: async () => [{ key: "policy-1", value: "Policy 1" }],
  };

  it("mounts the access procedures under app.accesses.access and reports its own version", async () => {
    const router = newCustomConnectorRouter({
      primitives,
      connectorVersion: "1.2.3",
    });
    const t = newConnectorTRPC();
    const caller = t.createCallerFactory(router)({ logger: createLogger() });

    const userId = await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(userId).toBe("user:person@example.com");

    const metadata = await caller.app.metadata.get();
    expect(metadata.connectorVersion).toBe("1.2.3");
    expect(metadata.frameworkVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("accepts a per-request primitives factory", async () => {
    const router = newCustomConnectorRouter({
      primitives: () => primitives,
      connectorVersion: "1.2.3",
    });
    const t = newConnectorTRPC();
    const caller = t.createCallerFactory(router)({ logger: createLogger() });

    const options = await caller.app.accesses.access.list({
      query: { type: "policy", appId: "app-1" },
    });
    expect(options).toEqual([{ key: "policy-1", value: "Policy 1" }]);
  });
});
