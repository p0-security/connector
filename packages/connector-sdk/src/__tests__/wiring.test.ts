import { createLogger, newConnectorTRPC } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { newCustomAppConnectorRouter } from "../router.ts";
import type { CustomAppConnectorActions, RequestContext } from "../schema.ts";

const newActions = (): CustomAppConnectorActions => ({
  validatePrincipal: async () => true,
  validateUserId: async () => true,
  getUser: async () => null,
  createUser: async (_context, userBody) => `user:${userBody.principal}`,
  deleteUser: async () => {},
  setPoliciesForUser: async () => {},
  list: async () => [{ key: "policy-1", value: "Policy 1" }],
});

/** The default actions with some of them swapped out. */
const newActionsWith =
  (overrides: Partial<CustomAppConnectorActions>) =>
  (): CustomAppConnectorActions => ({ ...newActions(), ...overrides });

/** The marker this application stamps onto the user ids it mints. */
const NAMESPACE_PREFIX = "p0_";

/** The requesters this application knows, whatever their access. */
const KNOWN_PRINCIPALS = new Set(["person@example.com"]);

/** A connector's two validators */
const namespaceValidators: Pick<
  CustomAppConnectorActions,
  "validatePrincipal" | "validateUserId"
> = {
  validatePrincipal: async (_context, principal) =>
    KNOWN_PRINCIPALS.has(principal),
  validateUserId: async (_context, userId) =>
    userId.startsWith(NAMESPACE_PREFIX),
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

describe("the namespace validators", () => {
  const newGuardedCaller = () =>
    newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith(namespaceValidators),
        connectorVersion: "1.2.3",
      })
    );

  it("admit a user the connector recognizes", async () => {
    const caller = newGuardedCaller();

    const userId = await caller.app.accesses.access.provisionUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-1", appId: "app-1" },
    });
    expect(userId).toBe("user:person@example.com");
  });

  it("guard the principal-keyed actions with validatePrincipal", async () => {
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

  it("guard the id-keyed actions with validateUserId", async () => {
    const caller = newGuardedCaller();

    await expect(
      caller.app.accesses.access.deleteUser({
        userId: "someone-elses-user",
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);

    await expect(
      caller.app.accesses.access.setPoliciesForUser({
        userId: "someone-elses-user",
        policies: ["policy-1"],
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);
  });

  it("receive the principal, not the whole user body", async () => {
    const seen: unknown[] = [];
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({
          validatePrincipal: async (_context, principal) => {
            seen.push(principal);
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
    expect(seen).toEqual(["person@example.com"]);
  });

  it("receive the request context, so checks can vary per request", async () => {
    const seen: string[] = [];
    const record = async (context: { appId: string }) => {
      seen.push(context.appId);
      return true;
    };
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({
          validatePrincipal: record,
          validateUserId: record,
        }),
        connectorVersion: "1.2.3",
      })
    );

    await caller.app.accesses.access.deleteUser({
      userId: "any-user",
      context: { requestId: "req-1", appId: "app-42" },
    });
    await caller.app.accesses.access.identifyUser({
      userBody: { principal: "person@example.com" },
      context: { requestId: "req-2", appId: "app-43" },
    });
    expect(seen).toEqual(["app-42", "app-43"]);
  });

  it("accept one shared implementation where a principal and a user id are the same thing", async () => {
    const seen: string[] = [];
    // Identical signatures — `(context, string) => Promise<boolean>` — so an
    // application that names accounts by the principal it receives has just
    // one thing to validate, and one function to do it with.
    const isKnownUser = async (_context: RequestContext, user: string) => {
      seen.push(user);
      return KNOWN_PRINCIPALS.has(user);
    };

    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActionsWith({
          validatePrincipal: isKnownUser,
          validateUserId: isKnownUser,
          createUser: async (_context, userBody) => userBody.principal,
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
        userId: "someone-elses-user",
        context: { requestId: "req-2", appId: "app-1" },
      })
    ).rejects.toThrow(/not namespaced/);

    expect(seen).toEqual(["person@example.com", "someone-elses-user"]);
  });

  it("let a connector opt out by returning true unconditionally", async () => {
    const caller = newCaller(
      newCustomAppConnectorRouter({
        actions: newActions,
        connectorVersion: "1.2.3",
      })
    );

    await expect(
      caller.app.accesses.access.deleteUser({
        userId: "not-namespaced-at-all",
        context: { requestId: "req-1", appId: "app-1" },
      })
    ).resolves.toBeNull();
  });
});
