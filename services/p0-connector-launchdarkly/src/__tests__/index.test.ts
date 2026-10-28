import { ConnectorError } from "@p0security/connector-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import * as connector from "../connector.ts";
import * as index from "../index.ts";
import { readToken } from "../secrets.ts";
import { INSTALL_INPUT, LAUNCHDARKLY_HOST } from "./fixtures.ts";

// The entry point creates its logger as it loads, so this has to come first.
vi.hoisted(() => {
  vi.stubEnv("LOG_LEVEL", "silent");
});

vi.mock("../secrets.ts");

/** A call as P0 sends it: the HTTP request it would have made, as the function's input. */
const invocation = (procedure: string, input?: unknown) => ({
  url: `https://connector.invalid/trpc/${procedure}${
    input === undefined
      ? ""
      : `?input=${encodeURIComponent(JSON.stringify(input))}`
  }`,
  method: "GET",
  headers: {},
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("the Lambda entry point", () => {
  it("answers a call sent as a function invocation", async () => {
    await expect(
      index.handler(invocation("launchdarkly.metadata.get"))
    ).resolves.toMatchObject({
      status: 200,
      body: { result: { data: { connectorVersion: packageJson.version } } },
    });
  });

  // What P0 reads of a failed check. The route logs through its context, so
  // this also needs the handler to give each call one.
  it("answers a failed check with its type and its step", async () => {
    vi.mocked(readToken).mockRejectedValue(
      new ConnectorError({
        type: "validation_error",
        message: "The secret is empty.",
        payload: { manager: "aws" },
      })
    );

    await expect(
      index.handler(
        invocation("launchdarkly.install.validation.get", INSTALL_INPUT)
      )
    ).resolves.toMatchObject({
      status: 412,
      body: {
        error: {
          data: {
            type: "validation_error",
            payload: { step: "secret", host: LAUNCHDARKLY_HOST },
          },
        },
      },
    });
  });

  it("serves the contract beside the handler", () => {
    expect(index).toMatchObject(connector);
  });
});
