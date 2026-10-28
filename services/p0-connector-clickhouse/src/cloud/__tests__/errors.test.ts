import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import { ORGANIZATION_ID } from "../../__tests__/fixtures.ts";
import { type Api, ClickHouseError } from "../api.ts";
import {
  callCloud,
  isForbidden,
  isKeyRejected,
  isNotFound,
  isOtherOrganization,
  retryDelay,
  toConnectorError,
} from "../errors.ts";

const failure = (
  status: number | undefined,
  {
    api = "cloud",
    messages = ["Something went wrong."],
    retryAfter,
  }: { api?: Api; messages?: string[]; retryAfter?: string } = {}
) =>
  new ClickHouseError({
    api,
    method: "GET",
    path: `/v1/organizations/${ORGANIZATION_ID}/services`,
    status,
    messages,
    retryAfter,
  });

const target = { organizationId: ORGANIZATION_ID, subject: "service prod" };

const mapped = (error: unknown) => {
  const result = toConnectorError(error, target);
  if (!(result instanceof ConnectorError)) throw new Error("not mapped");
  return result.data;
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
    [409, "validation_error"],
    [418, "unknown"],
    [undefined, "upstream_unavailable"],
  ])("maps %s to %s", (status, type) => {
    expect(mapped(failure(status)).type).toBe(type);
  });

  it("words a Cloud API 401 as the key rejected", () => {
    expect(mapped(failure(401)).message).toBe(
      "ClickHouse Cloud rejected P0's API key (401): the key ID or secret is wrong, or the key is disabled or expired. Check the key in its secret."
    );
  });

  // The Cloud API took the same key moments before.
  it("words a Query API 401 as the reader role missing, not the key wrong", () => {
    expect(
      mapped(failure(401, { api: "query", messages: ["Unauthorized"] })).message
    ).toBe(
      "ClickHouse Cloud refused to run P0's Query API endpoint on service prod (401): Unauthorized. Check that P0's API key has the Basic Service API Reader role, then try again."
    );
  });

  it("words a Cloud API 403 as a missing permission, quoting the reason", () => {
    expect(mapped(failure(403, { messages: ["Forbidden."] })).message).toBe(
      "ClickHouse Cloud refused P0's request about service prod (403): Forbidden. Check that P0's API key has the p0-connector role with every permission P0 needs."
    );
  });

  it("words a Query API 403 as the endpoint refused to run", () => {
    expect(
      mapped(failure(403, { api: "query", messages: ["ACCESS_DENIED"] }))
        .message
    ).toBe(
      "ClickHouse Cloud refused to run P0's Query API endpoint on service prod (403): ACCESS_DENIED. Check that P0's API key has the Basic Service API Reader role, then try again."
    );
  });

  it("names what wasn't found, and gives it as the query", () => {
    expect(mapped(failure(404))).toEqual({
      type: "object_not_found",
      message: `ClickHouse Cloud couldn't find service prod in the organization ${ORGANIZATION_ID}. Check that it still exists.`,
      payload: {
        organizationId: ORGANIZATION_ID,
        api: "cloud",
        query: "service prod",
        status: 404,
      },
    });
  });

  it("passes on how long to wait after a 429, without retrying", () => {
    expect(mapped(failure(429, { retryAfter: "30" }))).toEqual({
      type: "rate_limited",
      message:
        "ClickHouse Cloud rate-limited P0's API key. Retry in 30 seconds. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit.",
      payload: {
        organizationId: ORGANIZATION_ID,
        api: "cloud",
        status: 429,
        retryAfter: "30",
      },
    });
  });

  it("words the wait from an HTTP-date Retry-After, never quoting the date", () => {
    vi.useFakeTimers({ now: new Date("2026-10-21T07:27:00Z") });
    try {
      const retryAfter = "Wed, 21 Oct 2026 07:28:00 GMT";
      expect(mapped(failure(429, { retryAfter }))).toEqual({
        type: "rate_limited",
        message:
          "ClickHouse Cloud rate-limited P0's API key. Retry in 60 seconds. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit.",
        payload: {
          organizationId: ORGANIZATION_ID,
          api: "cloud",
          status: 429,
          retryAfter,
        },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("says 1 second after a 429 whose Retry-After date has passed", () => {
    expect(
      mapped(failure(429, { retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT" }))
        .message
    ).toBe(
      "ClickHouse Cloud rate-limited P0's API key. Retry in 1 second. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit."
    );
  });

  it("says a few minutes after a 429 without Retry-After", () => {
    expect(mapped(failure(429)).message).toBe(
      "ClickHouse Cloud rate-limited P0's API key. Retry in a few minutes. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit."
    );
  });

  it("words no answer from the Cloud API with its timeout and host", () => {
    expect(mapped(failure(undefined, { api: "cloud" })).message).toBe(
      "ClickHouse Cloud's API didn't answer within 10 seconds, or the connection dropped. Retry in a few minutes. If it keeps failing, check that the connector can reach api.clickhouse.cloud."
    );
  });

  it("words no answer from the Query API as a service that may be starting", () => {
    expect(mapped(failure(undefined, { api: "query" })).message).toBe(
      "ClickHouse Cloud's Query API didn't answer within 30 seconds, or the connection dropped. The service may be starting: retry in a minute. If it keeps failing, check that the connector can reach queries.clickhouse.cloud."
    );
  });

  it("words a 5xx as ClickHouse Cloud unavailable", () => {
    expect(mapped(failure(502)).message).toBe(
      "ClickHouse Cloud couldn't answer P0's request right now. Retry in a few minutes, and check status.clickhouse.com if it keeps failing."
    );
  });

  it("quotes the reason for a 400, without a doubled full stop", () => {
    expect(mapped(failure(400, { messages: ["Invalid body."] })).message).toBe(
      "ClickHouse Cloud refused P0's request about service prod (400): Invalid body"
    );
  });

  it("gives the status when ClickHouse Cloud gave no reason", () => {
    expect(mapped(failure(409, { messages: [] })).message).toBe(
      "ClickHouse Cloud refused P0's request about service prod (409): HTTP 409"
    );
  });

  it("leaves a ConnectorError as it is", () => {
    const error = new ConnectorError({
      type: "validation_error",
      message: "no",
      payload: {},
    });

    expect(toConnectorError(error, target)).toBe(error);
  });

  it("lets a bug through as it is", () => {
    const error = new TypeError("undefined is not a function");

    expect(toConnectorError(error, target)).toBe(error);
  });
});

describe("the status predicates", () => {
  it.each<[(error: unknown) => boolean, number[]]>([
    [isKeyRejected, [401]],
    [isForbidden, [403]],
    [isNotFound, [404]],
    [isOtherOrganization, [400, 403, 404]],
  ])("%o matches exactly %j", (predicate, statuses) => {
    for (const status of [400, 401, 403, 404, 409, 429, 500]) {
      expect(predicate(failure(status))).toBe(statuses.includes(status));
    }
    expect(predicate(failure(undefined))).toBe(false);
    expect(predicate(new Error("404"))).toBe(false);
  });
});

describe("retryDelay", () => {
  it("reads a number of seconds", () => {
    expect(retryDelay("30")).toBe(30_000);
  });

  it("reads an HTTP date as the time until it", () => {
    vi.useFakeTimers({ now: new Date("2026-10-21T07:27:00Z") });
    try {
      expect(retryDelay("Wed, 21 Oct 2026 07:28:00 GMT")).toBe(60_000);
      expect(retryDelay("Wed, 21 Oct 2026 07:26:00 GMT")).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([undefined, "", "soon"])("waits one window for %j", (value) => {
    expect(retryDelay(value)).toBe(10_000);
  });
});

describe("callCloud", () => {
  it("maps whatever the calls throw", async () => {
    await expect(
      callCloud(() => Promise.reject(failure(404)), target)
    ).rejects.toMatchObject({ data: { type: "object_not_found" } });
  });

  it("returns what the calls return", async () => {
    await expect(callCloud(() => Promise.resolve(7), target)).resolves.toBe(7);
  });
});
