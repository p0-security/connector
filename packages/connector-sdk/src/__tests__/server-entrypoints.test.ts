import * as core from "@p0security/connector-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  newCustomAppCloudRunServer,
  newCustomAppHttpServer,
} from "../deploy.ts";
import type { CustomAppConnectorActions } from "../schema.ts";

// Record which runner the SDK hands the router to, without starting a server.
vi.mock("@p0security/connector-core", async (importOriginal) => ({
  ...(await importOriginal<typeof core>()),
  runCloudRunConnector: vi.fn(),
  runHttpConnector: vi.fn(),
}));

const actions = (): CustomAppConnectorActions => ({
  validateUser: async () => true,
  userExists: async () => false,
  createUser: async () => {},
  deleteUser: async () => {},
  setPoliciesForUser: async () => {},
  list: async () => [],
});

afterEach(() => {
  vi.mocked(core.runCloudRunConnector).mockClear();
  vi.mocked(core.runHttpConnector).mockClear();
});

describe("newCustomAppCloudRunServer", () => {
  it("serves through runCloudRunConnector", () => {
    newCustomAppCloudRunServer({ actions, connectorVersion: "1.2.3" })();

    expect(core.runCloudRunConnector).toHaveBeenCalledWith(
      "app",
      expect.anything(),
      expect.any(Function)
    );
    expect(core.runHttpConnector).not.toHaveBeenCalled();
  });
});

describe("newCustomAppHttpServer", () => {
  it("serves through runHttpConnector", () => {
    newCustomAppHttpServer({ actions, connectorVersion: "1.2.3" })();

    expect(core.runHttpConnector).toHaveBeenCalledWith(
      "app",
      expect.anything(),
      expect.any(Function)
    );
    expect(core.runCloudRunConnector).not.toHaveBeenCalled();
  });

  it("doesn't start a server until it's called", () => {
    newCustomAppHttpServer({ actions, connectorVersion: "1.2.3" });

    expect(core.runHttpConnector).not.toHaveBeenCalled();
  });
});
