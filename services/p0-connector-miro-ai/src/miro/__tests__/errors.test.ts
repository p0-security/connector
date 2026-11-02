import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { MIRO_ROUTES, MiroError, type MiroFailure } from "../client.ts";
import { toConnectorError } from "../errors.ts";

const failed = (failure: MiroFailure) =>
  toConnectorError(new MiroError(MIRO_ROUTES.getBoards, failure));

describe("toConnectorError", () => {
  it.each([
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [400, "validation_error"],
    [409, "validation_error"],
    [429, "rate_limited"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
    [302, "validation_error"],
    [418, "validation_error"],
  ] as const)("types a %i as %s", (status, type) => {
    expect(failed({ kind: "status", status })).toMatchObject({
      data: { type, payload: { status } },
    });
  });

  it("types no answer as upstream_unavailable", () => {
    expect(failed({ kind: "unreachable", timedOut: true })).toMatchObject({
      data: {
        type: "upstream_unavailable",
        message:
          "The connector couldn't reach Miro: no answer within 10 seconds. Check that the connector's network can reach api.miro.com, and try again.",
      },
    });
  });

  it("types an answer Miro wouldn't give as unknown", () => {
    expect(failed({ kind: "unexpected", reason: "not_json" })).toMatchObject({
      data: { type: "unknown", payload: { reason: "not_json" } },
    });
  });

  // A message names the route template, never the URL with the team id.
  it("names the call by its route", () => {
    const error = failed({ kind: "status", status: 404 });
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.message).toContain("GET /v2/boards");
  });

  it("passes anything that isn't a Miro failure as it is", () => {
    const bug = new TypeError("a bug");
    expect(toConnectorError(bug)).toBe(bug);
  });
});
