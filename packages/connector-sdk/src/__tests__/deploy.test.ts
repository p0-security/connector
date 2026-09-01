import { describe, expect, it } from "vitest";

import {
  ConnectorError,
  type CustomAppConnectorActions,
  newCustomAppCloudRunServer,
  newCustomAppLambdaHandler,
} from "../index.ts";

const newActions = (): CustomAppConnectorActions => ({
  getUser: async () => null,
  createUser: async (_context, userBody) => `user:${userBody.principal}`,
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
      body: { result: { data: "user:person@example.com" } },
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
 * Namespacing is no longer a `validation` hook the framework calls on a
 * connector's behalf; a connector that needs it enforces it inside the
 * action that receives the value, which lets it reject with a classified
 * error rather than the bare `Error` the old hook threw.
 */
describe("a connector that enforces namespacing inside its own actions", () => {
  const newNamespacedActions = (): CustomAppConnectorActions => ({
    getUser: async () => null,
    createUser: async (_context, userBody) => {
      if (!userBody.principal.startsWith("p0_")) {
        throw new ConnectorError({
          type: "validation_error",
          message: `${userBody.principal} is not namespaced`,
          payload: { principal: userBody.principal },
        });
      }
      return `user:${userBody.principal}`;
    },
    deleteUser: async (_context, userId) => {
      if (!userId.startsWith("user:p0_")) {
        throw new ConnectorError({
          type: "validation_error",
          message: `${userId} is not namespaced`,
          payload: { userId },
        });
      }
    },
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

  it("admits a namespaced principal", async () => {
    expect(await provision("p0_alice")).toMatchObject({
      status: 200,
      body: { result: { data: "user:p0_alice" } },
    });
  });

  it("rejects an unnamespaced principal as a classified 412, not a 500", async () => {
    expect(await provision("alice")).toMatchObject({
      status: 412,
      body: {
        error: {
          message: "alice is not namespaced",
          data: { type: "validation_error", payload: { principal: "alice" } },
        },
      },
    });
  });

  it("rejects an unnamespaced id on delete", async () => {
    const res = await invoke(
      handler,
      "app.accesses.access.deleteUser",
      { userId: "user:someone-else", context: { requestId: "r", appId: "a" } },
      "mutation"
    );
    expect(res).toMatchObject({ status: 412 });
  });
});

describe("the CustomAppConnectorActions type", () => {
  it("does not accept a `validation` action", () => {
    const withValidation: CustomAppConnectorActions = {
      getUser: async () => null,
      createUser: async () => "u",
      deleteUser: async () => {},
      setPoliciesForUser: async () => {},
      list: async () => [],
      // @ts-expect-error -- `validation` is not part of the customer surface.
      validation: () => ({ user: null }),
    };
    expect(withValidation).toBeDefined();
  });
});
