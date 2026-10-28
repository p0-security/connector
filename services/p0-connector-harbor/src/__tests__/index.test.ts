import { afterEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../allowlist.ts";
import * as connector from "../connector.ts";
import * as index from "../index.ts";
import { readAdminCredential } from "../secrets.ts";
import { ADMIN_CREDENTIAL, HARBOR_HOST, INSTANCE } from "./fixtures.ts";

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
      index.handler(invocation("harbor.metadata.get"))
    ).resolves.toMatchObject({
      status: 200,
      body: { result: { data: { connectorVersion: packageJson.version } } },
    });
  });

  // What P0 reads of a failed check. The route logs through its context, so
  // this also needs the handler to give each call one.
  it("answers a failed check with its type and its step", async () => {
    vi.mocked(readAdminCredential).mockResolvedValue(ADMIN_CREDENTIAL);
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, undefined);

    await expect(
      index.handler(invocation("harbor.install.validation.get", INSTANCE))
    ).resolves.toMatchObject({
      status: 412,
      body: {
        error: {
          data: {
            type: "validation_error",
            payload: { step: "pattern", host: HARBOR_HOST },
          },
        },
      },
    });
  });

  it("serves the contract beside the handler", () => {
    expect(index).toMatchObject(connector);
  });
});
