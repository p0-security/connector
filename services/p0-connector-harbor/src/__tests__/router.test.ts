import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { connectorRouter } from "../router.ts";
import { INSTANCE, logger } from "./fixtures.ts";

const CONTEXT = {
  ...INSTANCE,
  requestId: "req-1",
  email: "alice@example.com",
  priorRole: null,
};

const ADMIN_CONTEXT = {
  ...INSTANCE,
  requestId: "req-1",
  email: "alice@example.com",
  wasSystemAdmin: false,
};

const connector = connectorRouter.createCaller({ logger });
const { projectRole, systemAdmin } = connector.harbor.accesses;

describe("the connector's router", () => {
  // Everything P0 can ask of the connector is in this list. tRPC has no
  // public way to list a router's procedures, so this reads its definition.
  it("exposes the project role and system administrator accesses, install validation and metadata, under one namespace", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "harbor.accesses.projectRole.deleteUser",
      "harbor.accesses.projectRole.identifyUser",
      "harbor.accesses.projectRole.list",
      "harbor.accesses.projectRole.provisionUser",
      "harbor.accesses.projectRole.setPoliciesForUser",
      "harbor.accesses.systemAdmin.deleteUser",
      "harbor.accesses.systemAdmin.identifyUser",
      "harbor.accesses.systemAdmin.list",
      "harbor.accesses.systemAdmin.provisionUser",
      "harbor.accesses.systemAdmin.setPoliciesForUser",
      "harbor.install.validation.get",
      "harbor.metadata.get",
    ]);
  });

  it("reports the workspace's version", async () => {
    await expect(connector.harbor.metadata.get()).resolves.toMatchObject({
      connectorVersion: packageJson.version,
    });
  });

  it("refuses input that doesn't parse, before it reaches a primitive", async () => {
    await expect(
      projectRole.list({
        query: {
          type: "project",
          context: { ...INSTANCE, url: "http://harbor.example.com" },
        },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  // A context that lost the recorded prior state must not reach a primitive: a missing `wasSystemAdmin` read as `false` would
  // take the flag from someone who had it.
  it.each([
    ["no wasSystemAdmin", { ...ADMIN_CONTEXT, wasSystemAdmin: undefined }],
    ["a null wasSystemAdmin", { ...ADMIN_CONTEXT, wasSystemAdmin: null }],
  ])("refuses a system administrator context with %s", async (_, context) => {
    await expect(
      systemAdmin.setPoliciesForUser({
        userId: "42",
        userBody: { instanceId: "p0-harbor", userId: "42" },
        // @ts-expect-error -- the context is wrong on purpose.
        context,
        policies: [{ systemAdmin: false }],
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});

// The user primitives answer without Harbor: a stubbed fetch that fails
// proves no call is made.
describe.each([
  ["project role", projectRole, CONTEXT],
  ["system administrator", systemAdmin, ADMIN_CONTEXT],
] as const)("the %s access's user routes", (_, access, context) => {
  const userBody = {
    userBody: { instanceId: "p0-harbor", userId: "42" },
    context,
  };

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("no Harbor call expected");
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // The framework's provisionUser is getUser ?? createUser, and createUser
  // refuses, so getUser has to answer.
  it("provisionUser answers the user body's id, without creating anyone", async () => {
    // @ts-expect-error -- each access takes its own context.
    await expect(access.provisionUser(userBody)).resolves.toBe("42");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("identifyUser answers the user body's id", async () => {
    // @ts-expect-error -- each access takes its own context.
    await expect(access.identifyUser(userBody)).resolves.toBe("42");
    expect(fetch).not.toHaveBeenCalled();
  });

  // Revoke calls it after setPoliciesForUser has ended the grant.
  it("deleteUser changes nothing", async () => {
    await expect(
      // @ts-expect-error -- each access takes its own context.
      access.deleteUser({ ...userBody, userId: "42" })
    ).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});
