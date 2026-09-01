import { createLogger, newConnectorTRPC } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { newCustomAppConnectorRouter } from "../router.ts";
import type { CustomAppConnectorActions } from "../schema.ts";

const newActions = (): CustomAppConnectorActions => ({
  getUser: async () => null,
  createUser: async (_context, userBody) => `user:${userBody.principal}`,
  deleteUser: async () => {},
  setPoliciesForUser: async () => {},
  list: async () => [{ key: "policy-1", value: "Policy 1" }],
});

const newCaller = (router: ReturnType<typeof newCustomAppConnectorRouter>) =>
  newConnectorTRPC().createCallerFactory(router)({ logger: createLogger() });

describe("newCustomAppConnectorRouter", () => {
  it("exposes exactly the five access procedures and the metadata endpoint", () => {
    const router = newCustomAppConnectorRouter({
      actions: newActions,
      connectorVersion: "1.2.3",
    });

    expect(Object.keys(router._def.procedures).sort()).toEqual([
      "app.accesses.access.deleteUser",
      "app.accesses.access.identifyUser",
      "app.accesses.access.list",
      "app.accesses.access.provisionUser",
      "app.accesses.access.setPoliciesForUser",
      "app.metadata.get",
    ]);
  });

  it("mounts the access procedures under app.accesses.access and reports its own version", async () => {
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActions,
        connectorVersion: "1.2.3",
      })
    );

    const userId = await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(userId).toBe("user:person@example.com");

    const metadata = await caller.app.metadata.get();
    expect(metadata.connectorVersion).toBe("1.2.3");
    expect(metadata.frameworkVersion).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("rebuilds the actions for each request", async () => {
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActions,
        connectorVersion: "1.2.3",
      })
    );

    const options = await caller.app.accesses.access.list({
      query: { type: "policy", appId: "app-1" },
    });
    expect(options).toEqual([{ key: "policy-1", value: "Policy 1" }]);
  });
});

describe("the router's mount keys", () => {
  it("stay literal rather than widening to an index signature", () => {
    const router = newCustomAppConnectorRouter({
      actions: newActions,
      connectorVersion: "1.2.3",
    });
    const caller = newCaller(router);

    // @ts-expect-error -- an index signature would admit any access name
    void caller.app.accesses.notAnAccess;
    // @ts-expect-error -- ...and any namespace
    void caller.notANamespace;

    expect(caller.app.accesses.access).toBeDefined();
  });
});
