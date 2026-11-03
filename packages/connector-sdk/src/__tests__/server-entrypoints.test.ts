import * as core from "@p0security/connector-core";
import { createLogger, newConnectorTRPC } from "@p0security/connector-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  newCustomAppCloudRunServer,
  newCustomAppHttpServer,
} from "../deploy.ts";
import { newCustomAppConnectorRouter } from "../router.ts";
import type { CustomAppConnectorActions } from "../schema.ts";

// Record which runner the SDK hands the router to, without starting a server.
vi.mock("@p0security/connector-core", async (importOriginal) => ({
  ...(await importOriginal<typeof core>()),
  runCloudRunConnector: vi.fn(),
  runHttpConnector: vi.fn(),
}));

// The key connector-core's runners put the audience mode under.
// `Symbol.for` makes it the same symbol here.
const AUDIENCE_CHECK_CONTEXT_KEY = Symbol.for(
  "@p0security/connector-core/audienceCheck"
);

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

describe("app.metadata.get on a Custom Application connector", () => {
  const metadata = (ctx: object) =>
    newConnectorTRPC()
      .createCallerFactory(
        newCustomAppConnectorRouter({ actions, connectorVersion: "1.2.3" })
      )({ logger: createLogger(), ...ctx })
      .app.metadata.get();

  it.each([true, false])(
    "reports audienceCheck: %j when the runner sets it",
    async (audienceCheck) => {
      await expect(
        metadata({ [AUDIENCE_CHECK_CONTEXT_KEY]: audienceCheck })
      ).resolves.toMatchObject({ connectorVersion: "1.2.3", audienceCheck });
    }
  );

  it("leaves audienceCheck out when no runner sets it", async () => {
    await expect(metadata({})).resolves.not.toHaveProperty("audienceCheck");
  });
});
