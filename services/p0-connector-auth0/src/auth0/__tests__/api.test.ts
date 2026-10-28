import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CLIENT_ID, CLIENT_SECRET, TENANT } from "../../__tests__/fixtures.ts";
import { newRecordingLogger, thrown } from "../../__tests__/helpers.ts";
import {
  Auth0Error,
  auth0Request,
  exchangeClientCredentials,
  rateLimitRetry,
  segment,
} from "../api.ts";

const ACCESS_TOKEN = "eyJ.SENTINELaccess.sig";

let logs: ReturnType<typeof newRecordingLogger>;
const fetchMock = vi.fn<typeof fetch>();

const reply = (
  status: number,
  body?: unknown,
  headers?: Record<string, string>
) =>
  // A fresh response per call: a retried request reads its body again.
  fetchMock.mockImplementation(
    async () =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers,
      })
  );

const get = (path = "/api/v2/roles") =>
  auth0Request({
    log: logs.log,
    tenant: TENANT,
    method: "GET",
    path,
    accessToken: ACCESS_TOKEN,
  });

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-15T09:00:00Z"));
  logs = newRecordingLogger();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  rateLimitRetry.waitMs = 0;
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  rateLimitRetry.waitMs = 10_000;
});

describe("auth0Request", () => {
  it("calls the tenant's host with the access token, and returns the body", async () => {
    reply(200, [{ id: "rol_1" }]);

    await expect(get()).resolves.toEqual([{ id: "rol_1" }]);

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(`https://${TENANT}/api/v2/roles`);
    expect(init?.headers).toEqual({
      Accept: "application/json",
      Authorization: `Bearer ${ACCESS_TOKEN}`,
    });
    expect(init?.redirect).toBe("error");
  });

  it("sends a JSON body with its content type", async () => {
    reply(204);

    await auth0Request({
      log: logs.log,
      tenant: TENANT,
      method: "POST",
      path: "/api/v2/users/u/roles",
      accessToken: ACCESS_TOKEN,
      body: { roles: ["rol_1"] },
    });

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.body).toBe('{"roles":["rol_1"]}');
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("returns undefined for an empty body", async () => {
    reply(204);

    await expect(get()).resolves.toBeUndefined();
  });

  it.each([
    "acme.auth0.com.evil.com",
    "evil.com",
    "acme.us.auth0.com:8443",
    "acme.us.auth0.com/x",
    "ACME.us.auth0.com",
    "auth0.com",
  ])("refuses %s as a tenant before anything is sent", async (tenant) => {
    const error = await thrown(() =>
      auth0Request({ log: logs.log, tenant, method: "GET", path: "/" })
    );

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("validation_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["acme.auth0.com", "acme.eu.auth0.com", "my-tenant-2.au.auth0.com"])(
    "takes %s as a tenant",
    async (tenant) => {
      reply(200, {});

      await auth0Request({ log: logs.log, tenant, method: "GET", path: "/" });

      expect(fetchMock).toHaveBeenCalledWith(
        `https://${tenant}/`,
        expect.anything()
      );
    }
  );

  it("reads a Management API error's message and code", async () => {
    reply(400, {
      statusCode: 400,
      error: "Bad Request",
      message: "Payload validation error",
      errorCode: "invalid_body",
    });

    const error = await thrown(get);

    expect(error).toBeInstanceOf(Auth0Error);
    expect(error).toMatchObject({
      status: 400,
      auth0Messages: ["Payload validation error"],
      errorCode: "invalid_body",
      retryAfter: undefined,
    });
  });

  it("reads the token endpoint's error and its description", async () => {
    reply(401, { error: "access_denied", error_description: "Unauthorized" });

    await expect(thrown(get)).resolves.toMatchObject({
      status: 401,
      auth0Messages: ["Unauthorized"],
      errorCode: "access_denied",
    });
  });

  it("doesn't take anything that isn't shaped like a code as one", async () => {
    reply(400, {
      message: "bad",
      errorCode: `Bearer ${ACCESS_TOKEN}`,
    });

    await expect(thrown(get)).resolves.toMatchObject({
      errorCode: undefined,
    });
  });

  it("doesn't take the HTTP reason for a code", async () => {
    reply(404, { statusCode: 404, error: "Not Found", message: "nope" });

    await expect(thrown(get)).resolves.toMatchObject({
      errorCode: undefined,
    });
  });

  it("has no messages for a body it can't read", async () => {
    fetchMock.mockResolvedValue(new Response("<html>", { status: 502 }));

    await expect(thrown(get)).resolves.toMatchObject({
      status: 502,
      auth0Messages: [],
    });
  });

  it("takes Retry-After on a 429", async () => {
    reply(429, { message: "Too Many Requests" }, { "retry-after": "7" });

    await expect(thrown(get)).resolves.toMatchObject({ retryAfter: "7" });
  });

  it("works out the wait from x-ratelimit-reset on a 429 without Retry-After", async () => {
    const reset = Math.floor(Date.now() / 1000) + 12;
    reply(429, {}, { "x-ratelimit-reset": String(reset) });

    await expect(thrown(get)).resolves.toMatchObject({ retryAfter: "12" });
  });

  describe("a 429", () => {
    // Each wait fires at once, and the test checks how long it would be.
    const realSetTimeout = globalThis.setTimeout;
    let waits: unknown[];
    let timers: { mockRestore: () => void };
    beforeEach(() => {
      rateLimitRetry.waitMs = 10_000;
      waits = [];
      timers = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((callback, ms) => {
          waits.push(ms);
          return realSetTimeout(callback, 0);
        });
    });
    afterEach(() => timers.mockRestore());

    const rateLimited = () =>
      new Response(
        JSON.stringify({ message: "Global limit has been reached" }),
        {
          status: 429,
          headers: { "retry-after": "1" },
        }
      );

    it("is retried after 10 seconds, and the answer that follows is returned", async () => {
      fetchMock
        .mockResolvedValueOnce(rateLimited())
        .mockResolvedValueOnce(new Response(JSON.stringify([{ id: "rol_1" }])));

      await expect(get()).resolves.toEqual([{ id: "rol_1" }]);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(waits).toEqual([10_000]);
    });

    it("retries a write, which Auth0 didn't act on", async () => {
      fetchMock
        .mockResolvedValueOnce(rateLimited())
        .mockResolvedValueOnce(new Response(null, { status: 204 }));

      await expect(
        auth0Request({
          log: logs.log,
          tenant: TENANT,
          method: "POST",
          path: "/api/v2/users/u/roles",
          accessToken: ACCESS_TOKEN,
          body: { roles: ["rol_1"] },
        })
      ).resolves.toBeUndefined();
      expect(fetchMock.mock.calls.map(([, init]) => init?.body)).toEqual([
        '{"roles":["rol_1"]}',
        '{"roles":["rol_1"]}',
      ]);
    });

    it("gives up after three retries, with when to retry", async () => {
      fetchMock.mockImplementation(async () => rateLimited());

      await expect(thrown(get)).resolves.toMatchObject({
        status: 429,
        retryAfter: "1",
      });
      expect(fetchMock).toHaveBeenCalledTimes(4);
      expect(waits).toEqual([10_000, 10_000, 10_000]);
    });
  });

  it("doesn't retry any other failure", async () => {
    reply(503, { message: "Service Unavailable" });

    await expect(thrown(get)).resolves.toMatchObject({ status: 503 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("never waits a negative time", async () => {
    reply(429, {}, { "x-ratelimit-reset": "1" });

    await expect(thrown(get)).resolves.toMatchObject({ retryAfter: "0" });
  });

  it("has no wait on a 429 without either header", async () => {
    reply(429, {});

    await expect(thrown(get)).resolves.toMatchObject({
      retryAfter: undefined,
    });
  });

  it("has no wait on anything but a 429", async () => {
    reply(503, {}, { "retry-after": "7" });

    await expect(thrown(get)).resolves.toMatchObject({
      retryAfter: undefined,
    });
  });

  it("fails without a status when Auth0 doesn't answer, and logs why", async () => {
    fetchMock.mockRejectedValue(
      new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") })
    );

    const error = await thrown(get);

    expect(error).toMatchObject({
      status: undefined,
      auth0Messages: ["fetch failed"],
    });
    expect(logs.error).toHaveBeenCalledWith(
      {
        method: "GET",
        path: "/api/v2/roles",
        failure: ["TypeError: fetch failed", "Error: ECONNREFUSED"],
      },
      "Auth0 request failed"
    );
  });

  it("cuts the access token out of fetch's own error", async () => {
    fetchMock.mockRejectedValue(
      new TypeError(`Invalid header value: "Bearer ${ACCESS_TOKEN}"`)
    );

    const error = await thrown(get);

    expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
    expect((error as Auth0Error).message).not.toContain(ACCESS_TOKEN);
    expect((error as Auth0Error).auth0Messages).toEqual([
      'Invalid header value: "[redacted]"',
    ]);
    expect(JSON.stringify(logs.error.mock.calls)).not.toContain(ACCESS_TOKEN);
  });

  it("cuts a secret the request carries out of Auth0's reply", async () => {
    reply(400, { message: `bad secret ${CLIENT_SECRET}` });

    const error = await thrown(() =>
      auth0Request({
        log: logs.log,
        tenant: TENANT,
        method: "POST",
        path: "/oauth/token",
        body: { client_secret: CLIENT_SECRET },
        secrets: [CLIENT_SECRET],
      })
    );

    expect((error as Auth0Error).auth0Messages).toEqual([
      "bad secret [redacted]",
    ]);
    expect(JSON.stringify(logs.warn.mock.calls)).not.toContain(CLIENT_SECRET);
  });

  it("fails without a status when the body is cut off", async () => {
    const response = new Response("{}", { status: 200 });
    vi.spyOn(response, "text").mockRejectedValue(new Error("terminated"));
    fetchMock.mockResolvedValue(response);

    await expect(thrown(get)).resolves.toMatchObject({ status: undefined });
  });
});

describe("segment", () => {
  it("encodes an id", () => {
    expect(segment("auth0|abc/def")).toBe("auth0%7Cabc%2Fdef");
  });

  it.each(["", ".", ".."])("refuses %j", (value) => {
    expect(() => segment(value)).toThrow(ConnectorError);
  });
});

describe("exchangeClientCredentials", () => {
  it("returns the token, its scopes and its lifetime", async () => {
    reply(200, {
      access_token: "a.b.c",
      scope: "read:users",
      expires_in: 86400,
      token_type: "Bearer",
    });

    await expect(
      exchangeClientCredentials({
        log: logs.log,
        tenant: TENANT,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      })
    ).resolves.toEqual({
      accessToken: "a.b.c",
      scope: "read:users",
      expiresIn: 86400,
    });
  });

  it("fails as unknown for a reply without a token, and logs no value", async () => {
    reply(200, { token: CLIENT_SECRET });

    const error = await thrown(() =>
      exchangeClientCredentials({
        log: logs.log,
        tenant: TENANT,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      })
    );

    expect((error as ConnectorError).data.type).toBe("unknown");
    expect(JSON.stringify(logs.warn.mock.calls)).not.toContain(CLIENT_SECRET);
  });
});

describe("auth0Request's edges", () => {
  // A code is a whole identifier, not one that starts like one.
  it("doesn't take a code with anything after the identifier", async () => {
    reply(400, { message: "bad", errorCode: "invalid_body extra" });

    await expect(thrown(get)).resolves.toMatchObject({
      errorCode: undefined,
    });
  });

  it("follows at most four causes when it logs why a request failed", async () => {
    let error: Error = new Error("cause 6");
    for (let n = 5; n >= 1; n--)
      error = new Error(`cause ${n}`, { cause: error });
    fetchMock.mockRejectedValue(error);

    await thrown(get);

    expect(logs.error).toHaveBeenCalledWith(
      expect.objectContaining({
        failure: [
          "Error: cause 1",
          "Error: cause 2",
          "Error: cause 3",
          "Error: cause 4",
          "Error: cause 5",
        ],
      }),
      "Auth0 request failed"
    );
  });

  it("says why it refuses a tenant", async () => {
    const error = await thrown(() =>
      auth0Request({
        log: logs.log,
        tenant: "evil.com",
        method: "GET",
        path: "/",
      })
    );

    expect((error as ConnectorError).data).toEqual({
      type: "validation_error",
      message:
        '"evil.com" isn\'t a canonical Auth0 tenant domain, such as acme.us.auth0.com.',
      payload: { tenant: "evil.com" },
    });
  });

  it("says which answer it couldn't read", async () => {
    reply(200, {});

    const error = await thrown(() =>
      exchangeClientCredentials({
        log: logs.log,
        tenant: TENANT,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      })
    );

    expect((error as ConnectorError).data).toEqual({
      type: "unknown",
      message:
        "Auth0 returned the token exchange's response in a shape the connector doesn't recognize.",
      payload: { what: "the token exchange's response" },
    });
    expect(logs.warn).toHaveBeenCalledWith(
      {
        what: "the token exchange's response",
        issues: [{ path: "access_token", code: "invalid_type" }],
      },
      "Auth0 returned a response the connector can't read"
    );
  });

  it("says why it refuses a path segment", () => {
    expect(() => segment("..")).toThrow(
      expect.objectContaining({
        data: {
          type: "validation_error",
          message: '".." isn\'t a valid Auth0 id.',
          payload: { segment: ".." },
        },
      })
    );
  });
});
