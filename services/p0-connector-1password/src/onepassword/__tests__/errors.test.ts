import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  AuthExpiredError,
  RateLimitExceededError,
} from "../../__tests__/fake-one-password.ts";
import { sdkFailureOf, toConnectorError } from "../errors.ts";

describe("toConnectorError", () => {
  it("passes the connector's own errors through", () => {
    const own = new ConnectorError({
      type: "object_not_found",
      message: "gone",
      payload: {},
    });

    expect(toConnectorError(own)).toBe(own);
  });

  it("words a rate limit, with the payload and the failure's facts", () => {
    expect(
      toConnectorError(
        Object.assign(new RateLimitExceededError("slow"), { status: 429 }),
        { vault: "v" }
      ).data
    ).toEqual({
      type: "rate_limited",
      message:
        "1Password is rate limiting the account's service account. Try again in a few minutes.",
      payload: { vault: "v", status: 429 },
    });
  });

  it("words an expired token", () => {
    expect(toConnectorError(new AuthExpiredError("expired")).data).toEqual({
      type: "insufficient_privileges",
      message:
        "1Password no longer accepts the account's service account token. Store a current service account token in the token secret.",
      payload: {},
    });
  });

  it("names anything else by its code and status, never its message", () => {
    const data = toConnectorError(
      Object.assign(new Error("ops_SENTINEL"), {
        code: "ECONNRESET",
        status: 502,
      })
    ).data;

    expect(data).toEqual({
      type: "unknown",
      message: "1Password failed the connector's call (ECONNRESET, HTTP 502).",
      payload: { code: "ECONNRESET", status: 502 },
    });
  });

  it("leaves the parentheses out for a failure that says nothing about itself", () => {
    expect(toConnectorError(new Error("x")).data.message).toBe(
      "1Password failed the connector's call."
    );
  });
});

describe("sdkFailureOf", () => {
  it.each([
    [new RateLimitExceededError("x"), "rate_limited"],
    [new AuthExpiredError("x"), "auth_expired"],
    [new Error("x"), undefined],
    ["RateLimitExceededError", undefined],
  ] as const)("reads %o as %s", (error, kind) => {
    expect(sdkFailureOf(error)).toBe(kind);
  });
});
