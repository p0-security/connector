import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { connectorRouter } from "../router.ts";
import { INSTANCE, logger } from "./fixtures.ts";

const connector = connectorRouter.createCaller({ logger });
const { globalRole } = connector.argocd.accesses;

// The router's input is what its parsers return, so P0 sends the namespace
// even when it is the default.
const PARSED_INSTANCE = { ...INSTANCE, namespace: "argocd" };

const CONTEXT = {
  ...PARSED_INSTANCE,
  requestId: "req-1",
  role: "role:readonly",
};

describe("the connector's router", () => {
  // Everything P0 can ask of the connector is in this list. tRPC has no
  // public way to list a router's procedures, so this reads its definition.
  it("exposes the global and project role accesses, install validation and metadata, under the argocd namespace", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "argocd.accesses.globalRole.deleteUser",
      "argocd.accesses.globalRole.identifyUser",
      "argocd.accesses.globalRole.list",
      "argocd.accesses.globalRole.provisionUser",
      "argocd.accesses.globalRole.setPoliciesForUser",
      "argocd.accesses.projectRole.deleteUser",
      "argocd.accesses.projectRole.identifyUser",
      "argocd.accesses.projectRole.list",
      "argocd.accesses.projectRole.provisionUser",
      "argocd.accesses.projectRole.setPoliciesForUser",
      "argocd.install.validation.get",
      "argocd.metadata.get",
    ]);
  });

  it("reports the workspace's version", async () => {
    await expect(connector.argocd.metadata.get()).resolves.toMatchObject({
      connectorVersion: packageJson.version,
    });
  });

  it("refuses input that doesn't parse, before it reaches a primitive", async () => {
    await expect(
      globalRole.list({
        query: {
          type: "role",
          context: { ...PARSED_INSTANCE, url: "http://argocd.example.com" },
        },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});

// Each access's user primitives answer without Argo CD: a stubbed fetch that fails
// proves no call is made.
describe("the global role access's user routes", () => {
  const userBody = {
    userBody: { instanceId: "p0-argocd", email: "alice@example.com" },
    context: CONTEXT,
  };

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("no Argo CD call expected");
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // The framework's provisionUser is getUser ?? createUser, and createUser
  // refuses, so getUser has to answer.
  it("provisionUser answers the user body's email, without creating anyone", async () => {
    await expect(globalRole.provisionUser(userBody)).resolves.toBe(
      "alice@example.com"
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("identifyUser answers the user body's email", async () => {
    await expect(globalRole.identifyUser(userBody)).resolves.toBe(
      "alice@example.com"
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  // Revoke calls it after setPoliciesForUser has removed the line.
  it("deleteUser changes nothing", async () => {
    await expect(
      globalRole.deleteUser({ ...userBody, userId: "alice@example.com" })
    ).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("the project role access's user routes", () => {
  const { projectRole } = connector.argocd.accesses;
  const context = {
    ...PARSED_INSTANCE,
    requestId: "req-1",
    project: "payments",
    role: "deployer",
  };
  const userBody = {
    userBody: { instanceId: "p0-argocd", email: "alice@example.com" },
    context,
  };

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("no Argo CD call expected");
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("provisionUser answers the user body's email, without creating anyone", async () => {
    await expect(projectRole.provisionUser(userBody)).resolves.toBe(
      "alice@example.com"
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("identifyUser answers the user body's email", async () => {
    await expect(projectRole.identifyUser(userBody)).resolves.toBe(
      "alice@example.com"
    );
  });

  it("deleteUser changes nothing", async () => {
    await expect(
      projectRole.deleteUser({ ...userBody, userId: "alice@example.com" })
    ).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});
