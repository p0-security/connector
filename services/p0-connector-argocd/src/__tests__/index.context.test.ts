import type * as connectorModule from "@p0security/connector";
import { describe, expect, it, vi } from "vitest";

import "../index.ts";
import { connectorRouter } from "../router.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const newCloudFunction = vi.hoisted(() =>
  vi.fn<typeof connectorModule.newCloudFunction>()
);

vi.mock("@p0security/connector", async (importOriginal) => ({
  ...(await importOriginal<typeof connectorModule>()),
  newCloudFunction,
}));

describe("the Lambda entry point's handler", () => {
  it("serves the connector's router", () => {
    expect(newCloudFunction).toHaveBeenCalledTimes(1);
    expect(newCloudFunction).toHaveBeenCalledWith(
      connectorRouter,
      expect.any(Function)
    );
  });

  // Every procedure logs through the logger in its context, and the routes
  // later tickets add will log.
  it("gives each call a context with a logger", async () => {
    const createContext = newCloudFunction.mock.calls[0]?.[1];

    await expect(
      // @ts-expect-error The invocation is left out: every call gets the same context.
      createContext?.()
    ).resolves.toEqual({
      logger: expect.objectContaining({ info: expect.any(Function) }),
    });
  });
});
