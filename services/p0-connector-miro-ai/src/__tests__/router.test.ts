import { describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { connectorRouter } from "../router.ts";
import { logger } from "./fixtures.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../secrets.ts");

const connector = connectorRouter.createCaller({ logger });

describe("the connector's router", () => {
  // Everything P0 can ask of the connector is in this list. tRPC has no
  // public way to list a router's procedures, so this reads its definition.
  // The board access joins it in INT-1110.
  it("exposes install validation and metadata, under one namespace", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "miro-ai.install.validation.get",
      "miro-ai.metadata.get",
    ]);
  });

  it("reports the workspace's version", async () => {
    await expect(connector["miro-ai"].metadata.get()).resolves.toMatchObject({
      connectorVersion: packageJson.version,
    });
  });

  // Metadata answers without reading the token or calling Miro.
  it("reports its metadata without calling Miro", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await connector["miro-ai"].metadata.get();

    expect(fetch).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
