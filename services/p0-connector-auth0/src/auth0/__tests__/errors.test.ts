import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { TENANT } from "../../__tests__/fixtures.ts";
import { Auth0Error } from "../api.ts";
import {
  TokenRejectedError,
  callAuth0,
  isConflict,
  isInvalidRequest,
  isNotFound,
  isTokenRejected,
  isUnauthorized,
  reasonOf,
  toConnectorError,
} from "../errors.ts";

const failure = (
  status: number | undefined,
  messages: string[] = [],
  extra: { errorCode?: string; retryAfter?: string } = {}
) =>
  new Auth0Error({
    method: "GET",
    path: "/api/v2/users/auth0%7Csecret-user",
    status,
    auth0Messages: messages,
    ...extra,
  });

const mapped = (error: unknown, subject?: string) => {
  const result = toConnectorError(error, { tenant: TENANT, subject });
  if (!(result instanceof ConnectorError)) throw result;
  return result.data;
};

describe("the status checks", () => {
  it.each([
    [isNotFound, [404], [400, 401, 409]],
    [isUnauthorized, [401], [403, 404]],
    [isConflict, [409], [400, 404]],
    [isInvalidRequest, [400, 409], [401, 404]],
    [isTokenRejected, [400, 401, 403], [404, 429, 500]],
  ] as const)("%o", (check, yes, no) => {
    for (const status of yes) expect(check(failure(status))).toBe(true);
    for (const status of no) expect(check(failure(status))).toBe(false);
    expect(check(failure(undefined))).toBe(false);
    expect(check(new Error("404"))).toBe(false);
  });
});

describe("reasonOf", () => {
  it("joins Auth0's messages, without a closing full stop", () => {
    expect(reasonOf(failure(400, ["One.", "Two."]))).toBe("One.; Two");
  });

  it("falls back to the status", () => {
    expect(reasonOf(failure(400))).toBe("HTTP 400");
    expect(reasonOf(failure(undefined))).toBe("HTTP error");
  });
});

describe("toConnectorError", () => {
  it("passes a connector error through", () => {
    const error = new ConnectorError({
      type: "unknown",
      message: "x",
      payload: {},
    });

    expect(toConnectorError(error, { tenant: TENANT })).toBe(error);
  });

  it("passes anything else through, so a bug stays a bug", () => {
    const error = new TypeError("boom");

    expect(toConnectorError(error, { tenant: TENANT })).toBe(error);
  });

  it("reports rejected credentials as insufficient_privileges", () => {
    expect(mapped(new TokenRejectedError(401, "Unauthorized"))).toEqual({
      type: "insufficient_privileges",
      message: `Auth0 tenant ${TENANT} didn't accept the connector's client credentials (401): Unauthorized. Check the client id in the P0 install and the client secret in the connector's secret, and that the application is authorized for the Auth0 Management API.`,
      payload: { reason: "token_rejected", tenant: TENANT, status: 401 },
    });
  });

  it.each([401, 403])("reports a %s as insufficient_privileges", (status) => {
    const data = mapped(
      failure(status, ["Insufficient scope, expected any of: read:roles"], {
        errorCode: "insufficient_scope",
      })
    );

    expect(data).toEqual({
      type: "insufficient_privileges",
      message: `Auth0 tenant ${TENANT} refused the connector's request (${status}): Insufficient scope, expected any of: read:roles. Check that the connector's Management API application is authorized with every scope P0 needs.`,
      payload: { tenant: TENANT, status, errorCode: "insufficient_scope" },
    });
  });

  it("reports a 404 as object_not_found, with what wasn't found as the query", () => {
    expect(mapped(failure(404), "role rol_1")).toEqual({
      type: "object_not_found",
      message: `Auth0 tenant ${TENANT} couldn't find role rol_1. Check that it still exists.`,
      payload: { tenant: TENANT, query: "role rol_1", status: 404 },
    });
  });

  it("says what it couldn't find in general when there's no subject", () => {
    expect(mapped(failure(404)).message).toBe(
      `Auth0 tenant ${TENANT} couldn't find what the connector asked for. Check that it still exists.`
    );
  });

  it("names the tenant as the query when there's no subject", () => {
    expect(mapped(failure(404)).payload).toMatchObject({ query: TENANT });
  });

  it("reports a 429 as rate_limited with when to retry, and doesn't retry", () => {
    expect(mapped(failure(429, [], { retryAfter: "12" }))).toEqual({
      type: "rate_limited",
      message: `Auth0 tenant ${TENANT} is rate limiting the connector. Retry in 12 seconds.`,
      payload: { tenant: TENANT, status: 429, retryAfter: "12" },
    });
  });

  it("reports a 429 without a wait as a few minutes", () => {
    expect(mapped(failure(429)).message).toBe(
      `Auth0 tenant ${TENANT} is rate limiting the connector. Retry in a few minutes.`
    );
  });

  it.each([500, 503])("reports a %s as upstream_unavailable", (status) => {
    expect(mapped(failure(status))).toEqual({
      type: "upstream_unavailable",
      message:
        "Auth0 couldn't answer the connector's request right now. Retry in a few minutes, and check status.auth0.com if it keeps failing.",
      payload: { tenant: TENANT, status },
    });
  });

  it("reports no answer as upstream_unavailable", () => {
    expect(mapped(failure(undefined))).toEqual({
      type: "upstream_unavailable",
      message: `The connector couldn't reach Auth0 tenant ${TENANT}. Check that it can reach ${TENANT}, then retry.`,
      payload: { tenant: TENANT },
    });
  });

  it.each([400, 409])(
    "reports a %s as validation_error with Auth0's reason",
    (status) => {
      expect(mapped(failure(status, ["Nope."]))).toEqual({
        type: "validation_error",
        message: `Auth0 tenant ${TENANT} refused the connector's request (${status}): Nope`,
        payload: { tenant: TENANT, status },
      });
    }
  );

  it("reports any other status as unknown", () => {
    expect(mapped(failure(418)).type).toBe("unknown");
  });

  // The path can carry a user id.
  it("never quotes the failed call's own message", () => {
    expect(JSON.stringify(mapped(failure(404)))).not.toContain("secret-user");
  });
});

describe("callAuth0", () => {
  it("returns what the calls return", async () => {
    await expect(callAuth0(async () => 3, { tenant: TENANT })).resolves.toBe(3);
  });

  it("maps a failure", async () => {
    await expect(
      callAuth0(
        async () => {
          throw failure(404);
        },
        { tenant: TENANT }
      )
    ).rejects.toMatchObject({ data: { type: "object_not_found" } });
  });
});
