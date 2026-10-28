import { describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import * as connector from "../connector.ts";
import * as index from "../index.ts";

// The entry point creates its logger as it loads, so this has to come first.
vi.hoisted(() => {
  vi.stubEnv("LOG_LEVEL", "silent");
});

/** A call as P0 sends it: the HTTP request it would have made, as the function's input. */
const invocation = (procedure: string) => ({
  url: `https://connector.invalid/trpc/${procedure}`,
  method: "GET",
  headers: {},
});

describe("the Lambda entry point", () => {
  it("answers a call sent as a function invocation", async () => {
    await expect(
      index.handler(invocation("argocd.metadata.get"))
    ).resolves.toMatchObject({
      status: 200,
      body: { result: { data: { connectorVersion: packageJson.version } } },
    });
  });

  // A procedure the router doesn't have is tRPC's 404.
  it("answers a procedure it doesn't serve with a 404", async () => {
    await expect(
      index.handler(invocation("argocd.install.nothing.get"))
    ).resolves.toMatchObject({ status: 404 });
  });

  it("serves the contract beside the handler", () => {
    expect(index).toMatchObject(connector);
  });
});
