import { describe, expect, it } from "vitest";

import {
  ConnectorError,
  type CustomAppConnectorActions,
  newCustomAppCloudRunServer,
  newCustomAppLambdaHandler,
} from "../index.ts";

const newActions = (): CustomAppConnectorActions => ({
  validateUser: async () => true,
  userExists: async () => false,
  createUser: async () => {},
  deleteUser: async () => {},
  setPoliciesForUser: async () => {},
  list: async () => [{ key: "policy-1", value: "Policy 1" }],
});

/**
 * Drives the handler exactly as a Lambda invoke does — a serialized HTTP
 * request, not a tRPC caller. The caller-based suite in `wiring.test.ts`
 * supplies the tRPC context by hand, so it cannot catch a deployment entry
 * point that fails to supply one.
 */
const invoke = (
  handler: (input: unknown) => Promise<unknown>,
  path: string,
  input: unknown,
  kind: "mutation" | "query"
) =>
  handler(
    kind === "query"
      ? {
          url: `https://connector.invalid/trpc/${path}?input=${encodeURIComponent(JSON.stringify(input))}`,
          method: "GET",
          headers: { "content-type": "application/json" },
        }
      : {
          url: `https://connector.invalid/trpc/${path}`,
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(input),
        }
  );

describe("newCustomAppLambdaHandler", () => {
  const handler = newCustomAppLambdaHandler({
    actions: newActions,
    connectorVersion: "1.2.3",
  });

  it("serves an access procedure end-to-end, with a context the SDK supplies", async () => {
    const res = await invoke(
      handler,
      "app.accesses.access.provisionUser",
      {
        userBody: { principal: "person@example.com" },
        context: { requestId: "req-1", appId: "app-1" },
      },
      "mutation"
    );

    expect(res).toMatchObject({
      status: 200,
      body: { result: { data: "person@example.com" } },
    });
  });

  it("serves the lister", async () => {
    const res = await invoke(
      handler,
      "app.accesses.access.list",
      { query: { type: "policy", appId: "app-1" } },
      "query"
    );

    expect(res).toMatchObject({
      status: 200,
      body: { result: { data: [{ key: "policy-1", value: "Policy 1" }] } },
    });
  });

  it("answers P0's install-time reachability check", async () => {
    const res = await invoke(handler, "app.metadata.get", undefined, "query");

    expect(res).toMatchObject({
      status: 200,
      body: { result: { data: { connectorVersion: "1.2.3" } } },
    });
  });

  it("passes a usable context to the actions factory on every request", async () => {
    let built = 0;
    const factoryHandler = newCustomAppLambdaHandler({
      actions: (ctx) => {
        built++;
        // Proves the context reached the factory rather than being undefined —
        // the framework's own middleware reads `ctx.logger` on every action.
        expect(ctx.logger).toBeDefined();
        return newActions();
      },
      connectorVersion: "1.2.3",
    });

    const res = await invoke(
      factoryHandler,
      "app.accesses.access.provisionUser",
      {
        userBody: { principal: "person@example.com" },
        context: { requestId: "req-1", appId: "app-1" },
      },
      "mutation"
    );

    expect(res).toMatchObject({ status: 200 });
    expect(built).toBe(1);
  });
});

describe("newCustomAppCloudRunServer", () => {
  it("returns a start function without binding a port", () => {
    // The bearer middleware admits only a Google-signed ID token for
    // $INVOKER_SA_EMAIL, so the served procedures are unreachable from a test;
    // they share their router and context factory with the Lambda path above.
    const run = newCustomAppCloudRunServer({
      actions: newActions,
      connectorVersion: "1.2.3",
    });

    expect(run).toBeTypeOf("function");
  });
});

/**
 * `validateUser` is the guard the framework calls on the connector's behalf,
 * before each action that touches a user. It returns a verdict rather than
 * throwing, and a `false` aborts the request before the action it guards runs.
 */
describe("a connector that namespaces its users", () => {
  const KNOWN_PRINCIPALS = new Set(["alice@example.com"]);

  const newNamespacedActions = (): CustomAppConnectorActions => ({
    validateUser: async (_context, user) =>
      KNOWN_PRINCIPALS.has(user.principal),
    userExists: async () => false,
    createUser: async () => {},
    deleteUser: async () => {},
    setPoliciesForUser: async () => {},
    list: async () => [],
  });

  const handler = newCustomAppLambdaHandler({
    actions: newNamespacedActions,
    connectorVersion: "1.2.3",
  });

  const provision = (principal: string) =>
    invoke(
      handler,
      "app.accesses.access.provisionUser",
      { userBody: { principal }, context: { requestId: "r", appId: "a" } },
      "mutation"
    );

  it("admits a principal it recognizes", async () => {
    expect(await provision("alice@example.com")).toMatchObject({
      status: 200,
      body: { result: { data: "alice@example.com" } },
    });
  });

  it("refuses an unknown principal without provisioning it", async () => {
    const created: string[] = [];
    const guardedHandler = newCustomAppLambdaHandler({
      actions: () => ({
        ...newNamespacedActions(),
        createUser: async (_context, user) => {
          created.push(user.principal);
        },
      }),
      connectorVersion: "1.2.3",
    });

    const res = await invoke(
      guardedHandler,
      "app.accesses.access.provisionUser",
      {
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "r", appId: "a" },
      },
      "mutation"
    );

    // A `false` verdict aborts with the framework's own error, which tRPC
    // reports as a 500. A connector wanting a status an operator can act on
    // throws ConnectorError from the action itself; see below.
    expect(res).toMatchObject({ status: 500 });
    expect(created).toEqual([]);
  });

  it("aborts a delete against a user the validator rejects, without calling deleteUser", async () => {
    const deleted: string[] = [];
    const guardedHandler = newCustomAppLambdaHandler({
      actions: () => ({
        ...newNamespacedActions(),
        deleteUser: async (_context, user) => {
          deleted.push(user.principal);
        },
      }),
      connectorVersion: "1.2.3",
    });

    const res = await invoke(
      guardedHandler,
      "app.accesses.access.deleteUser",
      {
        userId: "stranger@example.com",
        userBody: { principal: "stranger@example.com" },
        context: { requestId: "r", appId: "a" },
      },
      "mutation"
    );

    expect(res).toMatchObject({ status: 500 });
    expect(deleted).toEqual([]);
  });

  it("admits a delete against a user the validator accepts", async () => {
    expect(
      await invoke(
        handler,
        "app.accesses.access.deleteUser",
        {
          userId: "alice@example.com",
          userBody: { principal: "alice@example.com" },
          context: { requestId: "r", appId: "a" },
        },
        "mutation"
      )
    ).toMatchObject({ status: 200 });
  });
});

describe("a ConnectorError thrown by an action", () => {
  it("reaches P0 as a classified status carrying its message and payload", async () => {
    const handler = newCustomAppLambdaHandler({
      actions: () => ({
        ...newActions(),
        setPoliciesForUser: async (_context, user, policies) => {
          throw new ConnectorError({
            type: "validation_error",
            message: `${policies[0]} is not a well-formed policy`,
            payload: { principal: user.principal },
          });
        },
      }),
      connectorVersion: "1.2.3",
    });

    const res = await invoke(
      handler,
      "app.accesses.access.setPoliciesForUser",
      {
        userId: "alice@example.com",
        userBody: { principal: "alice@example.com" },
        policies: ["not a policy"],
        context: { requestId: "r", appId: "a" },
      },
      "mutation"
    );

    expect(res).toMatchObject({
      status: 412,
      body: {
        error: {
          message: "not a policy is not a well-formed policy",
          data: {
            type: "validation_error",
            payload: { principal: "alice@example.com" },
          },
        },
      },
    });
  });
});

describe("the CustomAppConnectorActions type", () => {
  it("requires the user validator", () => {
    // @ts-expect-error -- the validator is part of the surface a connector implements.
    const withoutPredicates: CustomAppConnectorActions = {
      userExists: async () => false,
      createUser: async () => {},
      deleteUser: async () => {},
      setPoliciesForUser: async () => {},
      list: async () => [],
    };
    expect(withoutPredicates).toBeDefined();
  });

  it("does not expose the framework's own `validation` hook", () => {
    const withValidation: CustomAppConnectorActions = {
      ...newActions(),
      // @ts-expect-error -- the SDK builds `validation` from `validateUser`.
      validation: () => ({ user: null }),
    };
    expect(withValidation).toBeDefined();
  });
});
