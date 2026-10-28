import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { API_KEY, KEY_ID, KEY_SECRET } from "../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
  thrown,
  thrownAs,
} from "../../__tests__/helpers.ts";
import { ClickHouseError } from "../../cloud/api.ts";
import { runEndpoint } from "../client.ts";

const CREDENTIALS = Buffer.from(`${KEY_ID}:${KEY_SECRET}`).toString("base64");
const ENDPOINT_ID = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
const URL_OK = `https://queries.clickhouse.cloud/run/${ENDPOINT_ID}`;

let logs: ReturnType<typeof newRecordingLogger>;
const fetchMock = vi.fn<typeof fetch>();

const reply = (
  status: number,
  body: string,
  headers?: Record<string, string>
) => fetchMock.mockResolvedValue(new Response(body, { status, headers }));

const run = (url = URL_OK, queryVariables?: Record<string, string>) =>
  runEndpoint({
    log: logs.log,
    key: API_KEY,
    endpoint: { name: "p0_objects", url },
    queryVariables,
  });

beforeEach(() => {
  logs = newRecordingLogger();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runEndpoint", () => {
  it("posts the documented body to the endpoint's URL, with Basic auth and version 2", async () => {
    reply(200, '{"engine":"View"}\n');

    await run(URL_OK, { database: "analytics", table: "v_users" });

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(URL_OK);
    expect(init?.method).toBe("POST");
    expect(init?.headers).toEqual({
      Accept: "application/x-ndjson, application/json",
      Authorization: `Basic ${CREDENTIALS}`,
      "Content-Type": "application/json",
      "x-clickhouse-endpoint-version": "2",
    });
    expect(JSON.parse(z.string().parse(init?.body))).toEqual({
      format: "JSONEachRow",
      queryVariables: { database: "analytics", table: "v_users" },
    });
    expect(init?.redirect).toBe("error");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("sends empty query variables when there are none", async () => {
    reply(200, "");

    await run();

    const body = z.string().parse(fetchMock.mock.calls[0]?.[1]?.body);
    expect(JSON.parse(body)).toEqual({
      format: "JSONEachRow",
      queryVariables: {},
    });
  });

  it("reads the rows line by line, skipping blank lines", async () => {
    reply(200, '{"1":1}\n\n{"name":"a\\nb"}\r\n  \n{"n":3}');

    await expect(run()).resolves.toEqual([
      { "1": 1 },
      { name: "a\nb" },
      { n: 3 },
    ]);
  });

  it("returns no rows for an empty body", async () => {
    reply(200, "");

    await expect(run()).resolves.toEqual([]);
  });

  it("fails as unknown on a line it can't read, without quoting the row", async () => {
    reply(200, `{"1":1}\nnot json ${KEY_SECRET}\n`);

    expect(await connectorError(() => run())).toEqual({
      type: "unknown",
      message:
        "ClickHouse Cloud returned rows from P0's Query API endpoint p0_objects that P0 can't read.",
      payload: { endpoint: "p0_objects" },
    });
    expect(JSON.stringify(logs.warn.mock.calls)).not.toContain(KEY_SECRET);
  });

  it.each([
    ["http", `http://queries.clickhouse.cloud/run/${ENDPOINT_ID}`],
    ["another host", `https://evil.example/run/${ENDPOINT_ID}`],
    [
      "a host under it",
      `https://queries.clickhouse.cloud.evil.example/run/${ENDPOINT_ID}`,
    ],
    [
      "a user part",
      `https://queries.clickhouse.cloud@evil.example/run/${ENDPOINT_ID}`,
    ],
    ["a port", `https://queries.clickhouse.cloud:8443/run/${ENDPOINT_ID}`],
    [
      "the old service path",
      `https://queries.clickhouse.cloud/service/${ENDPOINT_ID}/run`,
    ],
    ["a longer path", `${URL_OK}/x`],
    ["a query string", `${URL_OK}?format=TSV`],
    ["a fragment", `${URL_OK}#x`],
    [
      "an ID that isn't a UUID",
      "https://queries.clickhouse.cloud/run/../../v1",
    ],
    ["the Cloud API", `https://api.clickhouse.cloud/run/${ENDPOINT_ID}`],
    ["an empty URL", ""],
  ])("refuses a URL with %s, sending nothing", async (_case, url) => {
    expect(await connectorError(() => run(url))).toEqual({
      type: "unknown",
      message:
        "ClickHouse Cloud gave P0's Query API endpoint p0_objects a URL that isn't on queries.clickhouse.cloud, so P0 won't run it.",
      payload: { endpoint: "p0_objects" },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // `redirect: "error"` makes fetch reject a 3xx.
  it("fails without a status on a redirect", async () => {
    fetchMock.mockRejectedValue(
      new TypeError("fetch failed: redirect mode is set to error")
    );

    await expect(thrown(() => run())).resolves.toMatchObject({
      api: "query",
      status: undefined,
    });
  });

  it("fails without a status when the run times out", async () => {
    fetchMock.mockRejectedValue(
      new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError"
      )
    );

    await expect(thrown(() => run())).resolves.toMatchObject({
      api: "query",
      status: undefined,
      messages: ["The operation was aborted due to timeout"],
    });
  });

  it("passes on ClickHouse's own text for a failed run", async () => {
    reply(403, "Code: 497. DB::Exception: ACCESS_DENIED\n");

    const error = await thrown(() => run());

    expect(error).toBeInstanceOf(ClickHouseError);
    expect(error).toMatchObject({
      api: "query",
      method: "POST",
      status: 403,
      messages: ["Code: 497. DB::Exception: ACCESS_DENIED"],
    });
  });

  it("reads a JSON error body's message", async () => {
    reply(404, JSON.stringify({ error: "Endpoint not found" }));

    await expect(thrown(() => run())).resolves.toMatchObject({
      status: 404,
      messages: ["Endpoint not found"],
    });
  });

  it("takes Retry-After on a 429", async () => {
    reply(429, "slow down", { "retry-after": "5" });

    await expect(thrown(() => run())).resolves.toMatchObject({
      status: 429,
      retryAfter: "5",
    });
  });

  it.each([
    ["the key secret", `rejected ${KEY_SECRET}`],
    ["the credentials", `rejected ${CREDENTIALS}`],
    ["the Authorization header", `rejected Basic ${CREDENTIALS}`],
  ])("cuts %s out of an error that quotes it back", async (_case, body) => {
    reply(401, body);

    const error = await thrownAs(ClickHouseError, () => run());
    const text = JSON.stringify([
      error.messages,
      error.message,
      logs.warn.mock.calls,
    ]);

    expect(text).toContain("[redacted]");
    expect(text).not.toContain(KEY_SECRET);
    expect(text).not.toContain(CREDENTIALS);
  });

  it("cuts the key out of fetch's own error and its causes", async () => {
    fetchMock.mockRejectedValue(
      new TypeError(`Headers.append: "Basic ${CREDENTIALS}" is invalid`, {
        cause: new Error(`with ${KEY_SECRET}`),
      })
    );

    const error = await thrownAs(ClickHouseError, () => run());
    const text = JSON.stringify([error.messages, logs.warn.mock.calls]);

    expect(text).not.toContain(KEY_SECRET);
    expect(text).not.toContain(CREDENTIALS);
  });
});
