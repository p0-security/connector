import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { DockerHubError } from "../api.ts";
import {
  TokenRejectedError,
  callDockerHub,
  isInvalidRequest,
  isMissingScope,
  isNotFound,
  isTokenRejected,
  isUnauthorized,
  reasonOf,
  toConnectorError,
} from "../errors.ts";

const target = { org: "acme", username: "alice" };

// The path carries an email and an invite id, which P0 shouldn't post to a
// Slack or Teams channel.
const PATH =
  "/v2/orgs/acme/members?search=alice%40acme.com&invite=e36eca69-4cc8";

const dockerHubError = (
  status: number | undefined,
  dockerMessages: string[] = ["bad request", "the role is not valid"],
  retryAfter?: string
) =>
  new DockerHubError({
    method: "GET",
    path: PATH,
    status,
    dockerMessages,
    retryAfter,
  });

const dataOf = (error: unknown) => {
  if (!(error instanceof ConnectorError)) {
    throw new Error("expected a ConnectorError");
  }
  return error.data;
};

describe("toConnectorError", () => {
  // The design's table, row by row.
  it.each([
    [
      401,
      "insufficient_privileges",
      "Docker Hub refused the organization access token for acme (401). Check that the token has the Member Edit and Invite Edit scopes for acme.",
    ],
    [
      403,
      "insufficient_privileges",
      "Docker Hub refused the organization access token for acme (403). Check that the token has the Member Edit and Invite Edit scopes for acme.",
    ],
    [
      404,
      "object_not_found",
      "Docker Hub couldn't find alice in acme. Check that it still exists, and that the organization access token is for acme.",
    ],
    [
      429,
      "rate_limited",
      "Docker Hub is rate limiting the connector for acme. Retry in a few minutes.",
    ],
    [
      500,
      "upstream_unavailable",
      "Docker Hub couldn't answer the connector's request right now. Retry in a few minutes, and check dockerstatus.com if it keeps failing.",
    ],
    [
      503,
      "upstream_unavailable",
      "Docker Hub couldn't answer the connector's request right now. Retry in a few minutes, and check dockerstatus.com if it keeps failing.",
    ],
    [
      undefined,
      "upstream_unavailable",
      "The connector couldn't reach Docker Hub. Check that it can reach hub.docker.com, then retry.",
    ],
    [
      400,
      "validation_error",
      "Docker Hub refused the connector's request for acme (400): bad request; the role is not valid",
    ],
    [
      409,
      "validation_error",
      "Docker Hub refused the connector's request for acme (409): bad request; the role is not valid",
    ],
  ])(
    "maps status %s to %s, with a message that never names the path",
    (status, type, message) => {
      const error = dockerHubError(status);
      expect(error.message).toContain(PATH);

      const data = dataOf(toConnectorError(error, target));

      expect(data.type).toBe(type);
      expect(data.message).toBe(message);
      expect(JSON.stringify(data)).not.toContain(PATH);
      expect(JSON.stringify(data)).not.toContain("e36eca69");
    }
  );

  // Not in the table: nothing says what else Docker Hub answers with.
  it("maps any other status to unknown, quoting Docker Hub", () => {
    const data = dataOf(toConnectorError(dockerHubError(422), target));

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      "Docker Hub refused the connector's request for acme (422): bad request; the role is not valid"
    );
  });

  it("names the status when Docker Hub gave no reason", () => {
    const data = dataOf(toConnectorError(dockerHubError(409, []), target));

    expect(data.message).toBe(
      "Docker Hub refused the connector's request for acme (409): HTTP 409"
    );
  });

  // The 400 too: the requestor can't fix the token, so it's never theirs to.
  it.each([400, 401, 403])(
    "maps a token exchange refused with a %s to insufficient_privileges",
    (status) => {
      const data = dataOf(
        toConnectorError(new TokenRejectedError(status), target)
      );

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        reason: "token_rejected",
        org: "acme",
        status,
      });
      expect(data.message).toBe(
        `Docker Hub didn't accept the organization access token for acme (${status}). Check that the token in the connector's secret was created for acme, and that it hasn't expired or been revoked.`
      );
    }
  );

  // `query` is the field P0 reads off an `object_not_found`.
  it("locates a not-found by the member, or by the org when there's none", () => {
    expect(
      dataOf(toConnectorError(dockerHubError(404), target)).payload
    ).toEqual({ org: "acme", query: "acme/alice", status: 404 });

    const data = dataOf(toConnectorError(dockerHubError(404), { org: "acme" }));
    expect(data.payload).toEqual({ org: "acme", query: "acme", status: 404 });
    expect(data.message).toBe(
      "Docker Hub couldn't find acme. Check that it still exists, and that the organization access token is for acme."
    );
  });

  it("carries the status, and Retry-After when Docker Hub sent one", () => {
    expect(
      dataOf(toConnectorError(dockerHubError(429, [], "30"), target)).payload
    ).toEqual({ org: "acme", status: 429, retryAfter: "30" });
    expect(
      dataOf(toConnectorError(dockerHubError(undefined), target)).payload
    ).toEqual({ org: "acme" });
  });

  it("passes a ConnectorError through", () => {
    const error = new ConnectorError({
      type: "validation_error",
      message: "m",
      payload: {},
    });
    expect(toConnectorError(error, target)).toBe(error);
  });

  it("leaves anything else alone", () => {
    const error = new Error("a bug");
    expect(toConnectorError(error, target)).toBe(error);
  });
});

describe("callDockerHub", () => {
  it("returns what the call returns", async () => {
    await expect(callDockerHub(async () => "ok", target)).resolves.toBe("ok");
  });

  it("maps what the call throws", async () => {
    await expect(
      callDockerHub(async () => {
        throw dockerHubError(503);
      }, target)
    ).rejects.toMatchObject({ data: { type: "upstream_unavailable" } });
  });
});

// Every reading of a Docker Hub status is one of these.
describe("reading a status", () => {
  const STATUSES = [400, 401, 403, 404, 409, 429, 500];

  it.each([
    { name: "isNotFound", is: isNotFound, statuses: [404] },
    { name: "isUnauthorized", is: isUnauthorized, statuses: [401] },
    { name: "isMissingScope", is: isMissingScope, statuses: [401, 403] },
    { name: "isInvalidRequest", is: isInvalidRequest, statuses: [400, 409] },
    { name: "isTokenRejected", is: isTokenRejected, statuses: [400, 401, 403] },
  ])("$name is true for $statuses, and nothing else", ({ is, statuses }) => {
    expect(STATUSES.filter((status) => is(dockerHubError(status)))).toEqual(
      statuses
    );
    // Docker Hub not answering, and errors that aren't its own.
    expect(is(dockerHubError(undefined))).toBe(false);
    expect(is(new TokenRejectedError(401))).toBe(false);
    expect(is(new Error("404"))).toBe(false);
  });
});

describe("reasonOf", () => {
  it("joins Docker Hub's messages, or names the status", () => {
    expect(reasonOf(dockerHubError(400, ["a", "b"]))).toBe("a; b");
    expect(reasonOf(dockerHubError(409, []))).toBe("HTTP 409");
  });

  it("still gives a reason when there's no message and no status", () => {
    expect(reasonOf(dockerHubError(undefined, []))).toBe("HTTP error");
  });
});

describe("TokenRejectedError", () => {
  it("is named, and says which status Docker Hub answered the exchange with", () => {
    const error = new TokenRejectedError(401);

    expect(error.name).toBe("TokenRejectedError");
    expect(error.message).toBe(
      "Docker Hub refused the organization access token (401)"
    );
    expect(error.status).toBe(401);
  });
});
