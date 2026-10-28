import type * as connectorModule from "@p0security/connector";
import { describe, expect, it, vi } from "vitest";

import { connectorRouter } from "../router.ts";
// The Cloud Run entry point, which starts its server as it loads.
import "../run.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const runCloudRunConnector = vi.hoisted(() =>
  vi.fn<typeof connectorModule.runCloudRunConnector>()
);

vi.mock("@p0security/connector", async (importOriginal) => ({
  ...(await importOriginal<typeof connectorModule>()),
  runCloudRunConnector,
}));

describe("the Cloud Run entry point", () => {
  it("serves the connector's router", () => {
    expect(runCloudRunConnector).toHaveBeenCalledTimes(1);
    expect(runCloudRunConnector).toHaveBeenCalledWith(
      "P0 Harbor connector",
      connectorRouter,
      expect.any(Function)
    );
  });

  // Every procedure logs through the logger in its context.
  it("gives each request a context with a logger", async () => {
    const createContext = runCloudRunConnector.mock.calls[0]?.[2];

    await expect(
      // @ts-expect-error The Express request and response are left out: every request gets the same context.
      createContext?.()
    ).resolves.toEqual({
      logger: expect.objectContaining({ info: expect.any(Function) }),
    });
  });
});
