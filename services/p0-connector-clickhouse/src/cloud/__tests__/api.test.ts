import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  API_KEY,
  KEY_ID,
  KEY_SECRET,
  ORGANIZATION_ID,
  SERVICE_ID,
} from "../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
  thrown,
  thrownAs,
} from "../../__tests__/helpers.ts";
import {
  ClickHouseError,
  type Method,
  basicCredentials,
  cloudRequest,
  isAllowed,
  parseResponse,
  segment,
  withoutSecrets,
} from "../api.ts";

const CREDENTIALS = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString("base64");
const ORG = `/v1/organizations/${ORGANIZATION_ID}`;
const SERVICE = `${ORG}/services/${SERVICE_ID}`;
const ENDPOINT_ID = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";

let logs: ReturnType<typeof newRecordingLogger>;
const fetchMock = vi.fn<typeof fetch>();

const reply = (
  status: number,
  body?: unknown,
  headers?: Record<string, string>
) =>
  fetchMock.mockResolvedValue(
    new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers }
    )
  );

const get = (path = ORG) =>
  cloudRequest({ log: logs.log, key: API_KEY, method: "GET", path });

beforeEach(() => {
  logs = newRecordingLogger();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("cloudRequest", () => {
  it("calls api.clickhouse.cloud with Basic auth, refusing redirects, and returns the body", async () => {
    reply(200, { status: 200, result: { id: ORGANIZATION_ID } });

    await expect(get()).resolves.toEqual({
      status: 200,
      result: { id: ORGANIZATION_ID },
    });

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(`https://api.clickhouse.cloud${ORG}`);
    expect(init?.headers).toEqual({
      Accept: "application/json",
      Authorization: `Basic ${CREDENTIALS}`,
    });
    expect(init?.redirect).toBe("error");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("sends a JSON body with its content type", async () => {
    reply(201, { result: {} });

    await cloudRequest({
      log: logs.log,
      key: API_KEY,
      method: "POST",
      path: `${SERVICE}/query-api-endpoints`,
      body: { name: "p0_objects" },
    });

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.body).toBe('{"name":"p0_objects"}');
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("encodes query parameters", async () => {
    reply(200, { result: [] });

    await cloudRequest({
      log: logs.log,
      key: API_KEY,
      method: "GET",
      path: `${SERVICE}/query-api-endpoints`,
      search: { limit: "100", cursor: "a b&c" },
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `https://api.clickhouse.cloud${SERVICE}/query-api-endpoints?limit=100&cursor=a+b%26c`
    );
  });

  it("adds no query string for no parameters", async () => {
    reply(200, { result: [] });

    await cloudRequest({
      log: logs.log,
      key: API_KEY,
      method: "GET",
      path: `${ORG}/keys`,
      search: {},
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `https://api.clickhouse.cloud${ORG}/keys`
    );
  });

  it("returns undefined for an empty body", async () => {
    reply(200);

    await expect(get()).resolves.toBeUndefined();
  });

  it("reads the documented error body's message", async () => {
    reply(400, { status: 400, error: "Invalid organization", requestId: "r" });

    const error = await thrown(get);

    expect(error).toBeInstanceOf(ClickHouseError);
    expect(error).toMatchObject({
      api: "cloud",
      method: "GET",
      status: 400,
      messages: ["Invalid organization"],
      retryAfter: undefined,
    });
  });

  it("has no messages for a body it can't read", async () => {
    reply(502, { unexpected: true });

    await expect(thrown(get)).resolves.toMatchObject({
      status: 502,
      messages: [],
    });
  });

  it("passes on a text body, cut to 500 characters", async () => {
    reply(502, `<html>${"x".repeat(600)}</html>`);

    const error = await thrownAs(ClickHouseError, get);

    expect(error.messages[0]).toHaveLength(500);
  });

  // Cut short first, the 10 characters before the cut would be kept.
  it.each([
    ["the key secret", KEY_SECRET],
    ["the base64 credentials", CREDENTIALS],
    ["the Authorization value", `Basic ${CREDENTIALS}`],
  ])("cuts %s out before it cuts a message short", async (_case, secret) => {
    reply(400, {
      error: `${"x".repeat(490)}${secret} was rejected`,
    });

    const error = await thrownAs(ClickHouseError, get);

    const [message] = error.messages;
    expect(message).toBe(`${"x".repeat(490)}[redacted]`);
    expect(message).not.toContain(secret.slice(0, 10));
  });

  it("takes Retry-After on a 429", async () => {
    reply(429, { error: "Too Many Requests" }, { "retry-after": "7" });

    await expect(thrown(get)).resolves.toMatchObject({
      status: 429,
      retryAfter: "7",
    });
  });

  it("has no wait on a 429 without Retry-After", async () => {
    reply(429, {});

    await expect(thrown(get)).resolves.toMatchObject({
      retryAfter: undefined,
    });
  });

  it("ignores Retry-After on anything but a 429", async () => {
    reply(503, {}, { "retry-after": "7" });

    await expect(thrown(get)).resolves.toMatchObject({
      retryAfter: undefined,
    });
  });

  it("fails without a status when nothing answers, logging why without the key", async () => {
    fetchMock.mockRejectedValue(
      new TypeError("fetch failed", {
        cause: new Error(`connect ECONNREFUSED, sent Basic ${CREDENTIALS}`),
      })
    );

    const error = await thrown(get);

    expect(error).toMatchObject({
      status: undefined,
      messages: ["fetch failed"],
    });
    const logged = JSON.stringify(logs.warn.mock.calls);
    expect(logged).toContain("ECONNREFUSED");
    expect(logged).not.toContain(CREDENTIALS);
  });

  // `AbortSignal.timeout` rejects with a `TimeoutError`.
  it("fails without a status when the call times out", async () => {
    fetchMock.mockRejectedValue(
      new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError"
      )
    );

    await expect(thrown(get)).resolves.toMatchObject({
      status: undefined,
      messages: ["The operation was aborted due to timeout"],
    });
  });

  // `redirect: "error"` makes fetch reject a 3xx.
  it("fails without a status on a redirect", async () => {
    fetchMock.mockRejectedValue(new TypeError("fetch failed: redirect"));

    await expect(thrown(get)).resolves.toMatchObject({ status: undefined });
  });

  it("fails without a status when the body doesn't arrive", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: () => Promise.reject(new Error("terminated")),
    } as unknown as Response);

    await expect(thrown(get)).resolves.toMatchObject({
      status: undefined,
      messages: ["terminated"],
    });
  });

  it.each([
    ["the key secret", (s: string) => `bad ${s}`],
    ["the credentials", () => `bad ${CREDENTIALS}`],
    ["the Authorization header", () => `bad Basic ${CREDENTIALS}`],
  ])(
    "cuts %s out of a message ClickHouse Cloud quotes back",
    async (_case, quote) => {
      reply(400, { error: quote(KEY_SECRET) });

      const error = await thrownAs(ClickHouseError, get);
      const text = JSON.stringify([
        error.messages,
        error.message,
        logs.warn.mock.calls,
      ]);

      expect(text).toContain("[redacted]");
      expect(text).not.toContain(KEY_SECRET);
      expect(text).not.toContain(CREDENTIALS);
    }
  );

  it("cuts the Authorization header out of fetch's own error", async () => {
    fetchMock.mockRejectedValue(
      new TypeError(
        `Headers.append: "Basic ${CREDENTIALS}" is an invalid header value.`
      )
    );

    const error = await thrownAs(ClickHouseError, get);

    expect(JSON.stringify(error.messages)).not.toContain(CREDENTIALS);
  });

  it.each<[Method, string]>([
    ["GET", ORG],
    ["GET", `${ORG}/members`],
    ["GET", `${ORG}/keys`],
    ["GET", `${ORG}/services`],
    ["GET", SERVICE],
    ["GET", `${SERVICE}/query-api-endpoints`],
    ["POST", `${SERVICE}/query-api-endpoints`],
    ["GET", `${SERVICE}/query-api-endpoints/${ENDPOINT_ID}`],
    ["PUT", `${SERVICE}/query-api-endpoints/${ENDPOINT_ID}`],
    ["DELETE", `${SERVICE}/query-api-endpoints/${ENDPOINT_ID}`],
    ["GET", `${ORG}/roles`],
    ["POST", `${ORG}/roles`],
    ["PATCH", `${ORG}/roles/${ENDPOINT_ID}`],
    ["DELETE", `${ORG}/roles/${ENDPOINT_ID}`],
  ])("allows %s %s", (method, path) => {
    expect(isAllowed(method, path)).toBe(true);
  });

  it.each<[Method, string]>([
    ["PATCH", ORG],
    ["DELETE", ORG],
    ["GET", `${ORG}/keys/${ENDPOINT_ID}`],
    ["POST", `${ORG}/keys`],
    ["POST", `${ORG}/services`],
    ["PATCH", SERVICE],
    ["DELETE", SERVICE],
    ["GET", `${SERVICE}/serviceQueryEndpoint`],
    ["POST", `${SERVICE}/serviceQueryEndpoint`],
    ["DELETE", `${SERVICE}/query-api-endpoints`],
    ["PATCH", `${SERVICE}/query-api-endpoints/${ENDPOINT_ID}`],
    ["POST", `${SERVICE}/query-api-endpoints/${ENDPOINT_ID}`],
    ["GET", `${ORG}/roles/${ENDPOINT_ID}`],
    ["PUT", `${ORG}/roles/${ENDPOINT_ID}`],
    ["DELETE", `${ORG}/roles`],
    ["GET", "/v1/organizations"],
    ["GET", `${ORG}/`],
    ["GET", `${ORG}/services/../keys`],
    ["GET", `${ORG}/members/x`],
    ["GET", `${SERVICE}/query-api-endpoints/not-an-id`],
  ])("refuses %s %s before anything is sent", async (method, path) => {
    expect(isAllowed(method, path)).toBe(false);

    const { type } = await connectorError(() =>
      cloudRequest({ log: logs.log, key: API_KEY, method, path })
    );

    expect(type).toBe("validation_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("basicCredentials", () => {
  it("is base64 of the key ID and secret", () => {
    expect(
      Buffer.from(basicCredentials(API_KEY), "base64").toString("utf8")
    ).toBe(`${KEY_ID}:${KEY_SECRET}`);
  });
});

describe("withoutSecrets", () => {
  it("cuts any Basic credential, the key's or not", () => {
    expect(withoutSecrets(["sent Basic b3RoZXI6a2V5c2VjcmV0"], [])).toEqual([
      "sent [redacted]",
    ]);
  });

  // The install's messages name the role.
  it("leaves the Basic Service API Reader role's name alone", () => {
    expect(
      withoutSecrets(["Grant the Basic Service API Reader role"], [])
    ).toEqual(["Grant the Basic Service API Reader role"]);
  });
});

describe("segment", () => {
  it("takes a Cloud ID", () => {
    expect(segment(SERVICE_ID)).toBe(SERVICE_ID);
  });

  it.each(["", ".", "..", "a/b", `${SERVICE_ID}/x`, KEY_SECRET])(
    "refuses %j without quoting it",
    async (value) => {
      const data = await connectorError(async () => segment(value));

      expect(JSON.stringify(data)).not.toContain(KEY_SECRET);
    }
  );
});

describe("parseResponse", () => {
  it("returns what the schema reads", () => {
    expect(
      parseResponse({
        log: logs.log,
        schema: z.object({ name: z.string() }),
        data: { name: "Acme", extra: 1 },
        what: "the organization",
      })
    ).toEqual({ name: "Acme" });
  });

  it("fails as unknown, logging where each issue is without any value", async () => {
    const data = await connectorError(async () =>
      parseResponse({
        log: logs.log,
        schema: z.object({ name: z.string() }),
        data: { name: KEY_SECRET.length, other: KEY_SECRET },
        what: "the organization",
      })
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "ClickHouse Cloud returned the organization in a shape P0 doesn't recognize.",
      payload: { what: "the organization" },
    });
    expect(JSON.stringify(logs.warn.mock.calls)).not.toContain(KEY_SECRET);
  });
});
