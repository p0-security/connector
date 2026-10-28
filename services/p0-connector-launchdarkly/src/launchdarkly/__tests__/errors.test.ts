import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { LAUNCHDARKLY_HOST } from "../../__tests__/fixtures.ts";
import {
  LAUNCHDARKLY_ROUTES,
  type LaunchDarklyCall,
  LaunchDarklyError,
  type LaunchDarklyFailure,
  retryAfterSeconds,
} from "../api.ts";
import { callLaunchDarkly, toConnectorError } from "../errors.ts";

const READ = LAUNCHDARKLY_ROUTES.getMember;
const WRITE = LAUNCHDARKLY_ROUTES.patchMember;
const HOST = LAUNCHDARKLY_HOST;

const mapped = (
  failure: LaunchDarklyFailure,
  call: LaunchDarklyCall = READ
) => {
  const error = toConnectorError(new LaunchDarklyError(call, failure), HOST);
  if (!(error instanceof ConnectorError)) throw new Error("not mapped");
  return error.data;
};

describe("toConnectorError", () => {
  it.each([
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [400, "validation_error"],
    [405, "validation_error"],
    [409, "validation_error"],
    [422, "validation_error"],
    [429, "rate_limited"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
    [302, "validation_error"],
    [418, "validation_error"],
  ] as const)("maps a %i to %s", (status, type) => {
    const data = mapped({ kind: "status", status });

    expect(data.type).toBe(type);
    expect(data.payload).toEqual({ host: HOST, status });
    // The route's template, never a URL.
    expect(data.message).toContain(`${READ.method} ${READ.route}`);
  });

  it("maps no answer to upstream_unavailable", () => {
    expect(
      mapped({ kind: "unreachable", timedOut: false, code: "ECONNRESET" })
    ).toEqual({
      type: "upstream_unavailable",
      message: `The connector couldn't reach LaunchDarkly at ${HOST}: ECONNRESET. Check that the connector's network can reach it, and try again.`,
      payload: { host: HOST, code: "ECONNRESET" },
    });
    expect(mapped({ kind: "unreachable", timedOut: true }).message).toContain(
      "no answer within 10 seconds"
    );
  });

  it("maps an answer LaunchDarkly wouldn't give to unknown", () => {
    expect(mapped({ kind: "unexpected", reason: "wrong_shape" })).toEqual({
      type: "unknown",
      message: `LaunchDarkly at ${HOST} answered GET /api/v2/members/{id} with something the connector can't read (wrong_shape). Try again, and contact P0 support if it keeps happening.`,
      payload: { host: HOST, reason: "wrong_shape" },
    });
  });

  it("quotes LaunchDarkly's message on a refused write", () => {
    expect(
      mapped({ kind: "status", status: 400, message: "Invalid patch" }, WRITE)
    ).toEqual({
      type: "validation_error",
      message: `LaunchDarkly at ${HOST} refused PATCH /api/v2/members/{id} with 400: Invalid patch.`,
      payload: { host: HOST, status: 400 },
    });
    // The API keeps no message for a read, so there is nothing to quote.
    expect(mapped({ kind: "status", status: 400 }).message).toBe(
      `LaunchDarkly at ${HOST} refused GET /api/v2/members/{id} with 400.`
    );
  });

  it("says how long to wait on a 429 when LaunchDarkly says", () => {
    expect(mapped({ kind: "status", status: 429, retryAfter: 4 })).toEqual({
      type: "rate_limited",
      message: `LaunchDarkly at ${HOST} is limiting the connector's calls: it answered GET /api/v2/members/{id} with 429. Try again in 4 seconds.`,
      payload: { host: HOST, status: 429, retryAfter: 4 },
    });
    expect(mapped({ kind: "status", status: 429 }).message).toContain(
      "Try again later."
    );
  });

  it("passes anything else through as it is", () => {
    const bug = new TypeError("a bug");
    expect(toConnectorError(bug, HOST)).toBe(bug);
  });
});

describe("callLaunchDarkly", () => {
  it("maps what the calls throw", async () => {
    await expect(
      callLaunchDarkly(async () => {
        throw new LaunchDarklyError(READ, { kind: "status", status: 404 });
      }, HOST)
    ).rejects.toMatchObject({ data: { type: "object_not_found" } });
  });
});

describe("retryAfterSeconds", () => {
  const NOW = 1_700_000_000_000;

  it.each<[string, Record<string, string>, number | undefined]>([
    ["Retry-After", { "retry-after": "12" }, 12],
    ["X-Ratelimit-Reset", { "x-ratelimit-reset": String(NOW + 2500) }, 3],
    [
      "X-Ratelimit-Auth-Token-Reset",
      { "x-ratelimit-auth-token-reset": String(NOW + 9000) },
      9,
    ],
    [
      "several, by the latest",
      { "retry-after": "1", "x-ratelimit-reset": String(NOW + 5000) },
      5,
    ],
    ["a reset already past", { "x-ratelimit-reset": String(NOW - 5000) }, 0],
    ["none", {}, undefined],
    ["one that isn't a number", { "retry-after": "soon" }, undefined],
  ])("reads %s", (_case, headers, seconds) => {
    expect(retryAfterSeconds(new Headers(headers), NOW)).toBe(seconds);
  });
});
