import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { TailscaleError } from "../api.ts";
import {
  TokenRejectedError,
  attributeRefusalMessage,
  isAttributeRefusal,
  toConnectorError,
} from "../errors.ts";

const TARGET = { tailnet: "T1234CNTRL", subject: "device n1" };

const failure = (
  status: number | undefined,
  message?: string,
  retryAfter?: string
) =>
  new TailscaleError({
    method: "GET",
    path: "/api/v2/device/n1",
    status,
    tailscaleMessage: message,
    retryAfter,
  });

/** Tailscale's live answer to a token without the call's scope, and to a missing device. */
const notFound = (tokenScopes: readonly string[] | undefined) =>
  new TailscaleError({
    method: "GET",
    path: "/api/v2/device/n1",
    status: 404,
    tailscaleMessage: "not found",
    scope: "devices:core:read",
    tokenScopes,
  });

const heldScope404 = notFound(["devices:core:read", "users:read"]);

const mapped = (error: unknown) => {
  const result = toConnectorError(error, TARGET);
  expect(result).toBeInstanceOf(ConnectorError);
  return (result as ConnectorError).data;
};

describe("toConnectorError", () => {
  it.each([
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [429, "rate_limited"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
    [400, "validation_error"],
    [402, "validation_error"],
    [409, "validation_error"],
    [418, "unknown"],
  ])("maps %i to %s", (status, type) => {
    expect(mapped(failure(status, "nope")).type).toBe(type);
  });

  it("maps no answer to upstream_unavailable", () => {
    expect(mapped(failure(undefined)).type).toBe("upstream_unavailable");
  });

  it("carries retryAfter on a 429", () => {
    expect(mapped(failure(429, "too many requests", "30"))).toMatchObject({
      payload: { retryAfter: "30", status: 429 },
      message: expect.stringContaining("30 seconds"),
    });
  });

  it("quotes Tailscale's reason on a refusal", () => {
    expect(mapped(failure(400, "test(s) failed.")).message).toContain(
      "test(s) failed"
    );
  });

  it("names the plan on a 402", () => {
    expect(mapped(failure(402, "payment required")).message).toContain(
      "Premium or Enterprise"
    );
  });

  // The error's own message carries the path, which can hold a device id.
  it("never quotes the request path", () => {
    for (const status of [401, 403, 404, 429, 500, 400]) {
      expect(mapped(failure(status, "x")).message).not.toContain("/api/v2");
    }
  });

  it("names the subject of a 404 in the payload", () => {
    expect(mapped(failure(404)).payload).toMatchObject({ query: "device n1" });
  });

  it("points a 404 at the Tailnet ID only when the subject's absence means the tailnet", () => {
    expect(mapped(failure(404)).message).toContain("Tailnet ID");
    const ownMissing = toConnectorError(heldScope404, {
      ...TARGET,
      missingMeansTailnet: false,
    });
    expect(ownMissing).toBeInstanceOf(ConnectorError);
    expect((ownMissing as ConnectorError).data.message).toBe(
      "Tailscale tailnet T1234CNTRL couldn't find device n1."
    );
  });

  it("maps a rejected credential to insufficient_privileges", () => {
    expect(mapped(new TokenRejectedError(401, "invalid client"))).toMatchObject(
      {
        type: "insufficient_privileges",
        payload: { reason: "token_rejected", status: 401 },
      }
    );
  });

  it("names the missing scope on a 404 to a token known to lack it", () => {
    expect(mapped(notFound(["users:read"]))).toEqual({
      type: "insufficient_privileges",
      message:
        'The connector\'s Tailscale credential for tailnet T1234CNTRL lacks devices:core:read, which P0 needs for device n1 (Tailscale answered "not found"). Add devices:core:read to the credential, then retry.',
      payload: {
        tailnet: "T1234CNTRL",
        missing: "devices:core:read",
        status: 404,
      },
    });
  });

  it("takes a write scope as covering its read on a 404", () => {
    expect(mapped(notFound(["devices:core"])).type).toBe("object_not_found");
  });

  it("says a 404 may be a missing scope when the token's scopes aren't known", () => {
    const error = toConnectorError(notFound(undefined), {
      ...TARGET,
      missingMeansTailnet: false,
    });
    expect((error as ConnectorError).data).toMatchObject({
      type: "object_not_found",
      message:
        "Tailscale tailnet T1234CNTRL couldn't find device n1. Tailscale also answers \"not found\" when the connector's Tailscale credential lacks the scope a call needs, so check that it holds devices:core:read.",
    });
  });

  it("says nothing of scopes on a 404 to a token known to hold the scope", () => {
    expect(mapped(heldScope404).message).not.toContain("scope");
  });

  it("maps Tailscale's refusal of a scope the OAuth client lacks to a credential error naming the scopes", () => {
    const refusal = new TokenRejectedError(
      403,
      'OAuth client cannot grant scopes "devices:core:read devices:posture_attributes policy_file"',
      ["policy_file", "devices:core:read", "devices:posture_attributes"]
    );
    expect(mapped(refusal)).toEqual({
      type: "insufficient_privileges",
      message:
        "Tailscale won't give the connector a token with policy_file, devices:core:read, devices:posture_attributes for tailnet T1234CNTRL (403): OAuth client cannot grant scopes \"devices:core:read devices:posture_attributes policy_file\". The connector's OAuth client lacks at least one of these scopes. Add the missing ones to it, then retry.",
      payload: {
        reason: "scopes_refused",
        tailnet: "T1234CNTRL",
        status: 403,
        scopes: "policy_file devices:core:read devices:posture_attributes",
      },
    });
  });

  it.each([
    ["a 403 for another reason", 403, "forbidden", ["users:read"]],
    [
      "a refusal of an exchange that asked for no scope",
      403,
      'OAuth client cannot grant scopes ""',
      [],
    ],
  ])("keeps %s a plain credential refusal", (_name, status, reason, scopes) => {
    expect(
      mapped(new TokenRejectedError(status, reason, scopes)).payload
    ).toMatchObject({ reason: "token_rejected" });
  });

  it("passes anything else through", () => {
    const bug = new RangeError("bug");
    expect(toConnectorError(bug, TARGET)).toBe(bug);
  });
});

describe("attributeRefusalMessage", () => {
  const refusal = (status: number, message?: string) => {
    const error = failure(status, message);
    if (!isAttributeRefusal(error)) throw new Error("not a refusal");
    return attributeRefusalMessage(TARGET.tailnet, error);
  };

  it("quotes Tailscale's reason, so a 400 from the request itself shows", () => {
    expect(refusal(400, "invalid expiry.")).toBe(
      "Tailnet T1234CNTRL refused a custom device attribute (400): invalid expiry. P0 sets posture attributes, which need a Premium or Enterprise plan, and a credential with devices:posture_attributes."
    );
  });

  it("names only the status when Tailscale gives no reason", () => {
    expect(refusal(403)).toBe(
      "Tailnet T1234CNTRL refused a custom device attribute (403). P0 sets posture attributes, which need a Premium or Enterprise plan, and a credential with devices:posture_attributes."
    );
  });
});
