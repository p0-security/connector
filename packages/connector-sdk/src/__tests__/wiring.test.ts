import { createLogger, newConnectorTRPC } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { newCustomAppConnectorRouter } from "../router.ts";
import type { CustomAppConnectorActions, RequestContext } from "../schema.ts";

const newActions = (): CustomAppConnectorActions => ({
  validateUser: async () => true,
  userExists: async () => false,
  createUser: async () => {},
  deleteUser: async () => {},
  setPoliciesForUser: async () => {},
  list: async () => [{ key: "policy-1", value: "Policy 1" }],
});

/** The default actions with some of them swapped out. */
const newActionsWith =
  (overrides: Partial<CustomAppConnectorActions>) =>
  (): CustomAppConnectorActions => ({ ...newActions(), ...overrides });

/** The requesters this application knows, whatever their access. */
const KNOWN_PRINCIPALS = new Set(["person@example.com"]);

/** A connector's one user validator. */
const userValidator: Pick<CustomAppConnectorActions, "validateUser"> = {
  validateUser: async (_context, user) => KNOWN_PRINCIPALS.has(user.principal),
};

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
    expect(userId).toBe("person@example.com");

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

describe("the user validator", () => {
  const newGuardedCaller = () =>
    newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith(userValidator),
        connectorVersion: "1.2.3",
      })
    );

  it("admit a user the connector recognizes", async () => {
    const caller = newGuardedCaller();

    const userId = await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(userId).toBe("person@example.com");
  });

  it("guards the actions that take only a user body", async () => {
    const caller = newGuardedCaller();

    await expect(
      caller.app.accesses.access.provisionUser({
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);

    await expect(
      caller.app.accesses.access.identifyUser({
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);
  });

  it("guards the actions that also carry a user id", async () => {
    const caller = newGuardedCaller();

    await expect(
      caller.app.accesses.access.deleteUser({
        userId: "stranger@example.com",
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);

    await expect(
      caller.app.accesses.access.setPoliciesForUser({
        userId: "stranger@example.com",
        userBody: { principal: "stranger@example.com" },
        policies: ["policy-1"],
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);
  });

  it("receives the whole user body, not just the principal", async () => {
    const seen: unknown[] = [];
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({
          validateUser: async (_context, user) => {
            seen.push(user);
            return true;
          },
        }),
        connectorVersion: "1.2.3",
      })
    );

    await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(seen).toEqual([{ principal: "person@example.com" }]);
  });

  it("receives the request context, so checks can vary per request", async () => {
    const seen: string[] = [];
    const record = async (context: RequestContext) => {
      seen.push(context.appId);
      return true;
    };
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({ validateUser: record }),
        connectorVersion: "1.2.3",
      })
    );

    await caller.app.accesses.access.deleteUser({
      userId: "person@example.com",
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-42" },
    });
    await caller.app.accesses.access.identifyUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-2", appId: "app-43" },
    });
    expect(seen).toEqual(["app-42", "app-43"]);
  });

  it("runs on the body of every user-keyed action, id-carrying ones included", async () => {
    const seen: string[] = [];
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({
          validateUser: async (_context, user) => {
            seen.push(user.principal);
            return KNOWN_PRINCIPALS.has(user.principal);
          },
        }),
        connectorVersion: "1.2.3",
      })
    );

    const userId = await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(userId).toBe("person@example.com");

    await expect(
      caller.app.accesses.access.deleteUser({
        userId: "stranger@example.com",
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "req-2", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);

    expect(seen).toEqual(["person@example.com", "stranger@example.com"]);
  });

  it("lets a connector opt out by returning true unconditionally", async () => {
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActions,
        connectorVersion: "1.2.3",
      })
    );

    await expect(
      caller.app.accesses.access.deleteUser({
        userId: "not-namespaced-at-all",
        userBody: { principal: "not-namespaced-at-all" },
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).resolves.toBeNull();
  });
});
