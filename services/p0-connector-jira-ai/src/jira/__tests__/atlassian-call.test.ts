import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type Reply,
  connectorErrorOf,
  jsonResponse,
  logger,
} from "../../__tests__/fixtures.ts";
import {
  ATTEMPT_TIMEOUT_MS,
  MAX_ATTEMPTS,
  REQUEST_BUDGET_MS,
  callAtlassian,
} from "../atlassian-call.ts";

const URL = "https://api.atlassian.com/ex/jira/x/rest/api/3/role";

/** A `fetch` that answers each call with the next of `answers`. */
const answering = (...answers: (Error | Reply)[]) => {
  const fetch = vi.fn(async (_url: string, _init: RequestInit) => {
    const next = answers.shift();
    if (next === undefined) throw new Error("no answer left");
    if (next instanceof Error) throw next;
    return jsonResponse(next);
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
};

// The clock starts at 0, so a request that starts with the test ends here.
const call = (repeatable = true, deadline = REQUEST_BUDGET_MS) =>
  callAtlassian({
    url: URL,
    init: { method: "GET" },
    repeatable,
    operation: "list roles",
    deadline,
    logger,
  });

/** The error `fetch` throws when an attempt's signal times out. */
const timeoutError = () =>
  Object.assign(new Error("timed out"), { name: "TimeoutError" });

/** Lets every pending promise run, without moving the clock. */
const flush = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers({ now: 0 });
  // The longest backoff, so the waits are known.
  vi.spyOn(Math, "random").mockReturnValue(1);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("callAtlassian", () => {
  it("retries a 5xx after a backoff, then returns the answer", async () => {
    const fetch = answering({ status: 503 }, { status: 200, body: {} });

    const result = call();
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);

    expect((await result).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("doubles the backoff each retry", async () => {
    const fetch = answering(
      { status: 500 },
      { status: 500 },
      { status: 500 },
      { status: 200, body: {} }
    );

    const result = call();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetch).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(fetch).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(4_000);

    expect((await result).status).toBe(200);
  });

  it("waits out a Retry-After in seconds on a 429", async () => {
    const fetch = answering(
      { status: 429, headers: { "Retry-After": "5" } },
      { status: 200, body: {} }
    );

    const result = call();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);

    expect((await result).status).toBe(200);
  });

  it("waits out a Retry-After given as a date", async () => {
    const fetch = answering(
      {
        status: 429,
        headers: { "Retry-After": new Date(3_000).toUTCString() },
      },
      { status: 200, body: {} }
    );

    const result = call();
    await vi.advanceTimersByTimeAsync(2_999);
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);

    expect((await result).status).toBe(200);
  });

  it("returns the last failure after the last attempt", async () => {
    const fetch = answering(
      ...Array.from({ length: MAX_ATTEMPTS }, () => ({ status: 502 }))
    );

    const result = call();
    await vi.runAllTimersAsync();

    expect((await result).status).toBe(502);
    expect(fetch).toHaveBeenCalledTimes(MAX_ATTEMPTS);
  });

  it("fails with rate_limited when a Retry-After would pass the deadline", async () => {
    const fetch = answering(
      { status: 429, headers: { "Retry-After": "12" } },
      { status: 429, headers: { "Retry-After": "12" } },
      { status: 429, headers: { "Retry-After": "12" } },
      { status: 200, body: {} }
    );

    const result = call();
    result.catch(() => undefined);
    await vi.runAllTimersAsync();

    // 12 s and 12 s fit in the 30 s budget. A third 12 s doesn't.
    const failure = await connectorErrorOf(result);
    expect(failure.data.type).toBe("rate_limited");
    expect(failure.message).toBe(
      "Atlassian is rate limiting the connector, so it couldn't list roles in time. Try the request again in a few minutes."
    );
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(Date.now()).toBe(24_000);
  });

  it("fails with upstream_unavailable when a backoff would pass the deadline", async () => {
    const fetch = answering({ status: 503 }, { status: 200, body: {} });

    const result = call(true, 500);
    result.catch(() => undefined);
    await vi.runAllTimersAsync();

    await expect(connectorErrorOf(result)).resolves.toMatchObject({
      data: { type: "upstream_unavailable" },
      message:
        "Atlassian is unavailable, so the connector couldn't list roles in time. Try the request again in a few minutes.",
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("sends nothing once the deadline has passed", async () => {
    const fetch = answering({ status: 200, body: {} });

    await expect(connectorErrorOf(call(true, 0))).resolves.toMatchObject({
      data: { type: "upstream_unavailable" },
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails as out of time when an attempt times out at the deadline", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        await vi.advanceTimersByTimeAsync(3_000);
        throw timeoutError();
      })
    );

    await expect(connectorErrorOf(call(true, 3_000))).resolves.toMatchObject({
      data: { type: "upstream_unavailable" },
    });
  });

  it("cuts an attempt's timeout to the time left before the deadline", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    answering({ status: 503 }, { status: 200, body: {} });

    const result = call(true, 10_500);
    await vi.runAllTimersAsync();
    await result;

    // The first attempt gets the full timeout. The second starts after a
    // 1 s backoff, so it gets what is left.
    expect(timeout.mock.calls).toEqual([[ATTEMPT_TIMEOUT_MS], [9_500]]);
  });

  it("retries a network failure or a timeout", async () => {
    const fetch = answering(new TypeError("fetch failed"), timeoutError(), {
      status: 200,
      body: {},
    });

    const result = call();
    await vi.runAllTimersAsync();

    expect((await result).status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("throws the last network failure after the last attempt", async () => {
    answering(
      ...Array.from(
        { length: MAX_ATTEMPTS },
        (_, attempt) => new TypeError(`failure ${attempt + 1}`)
      )
    );

    const result = call();
    result.catch(() => undefined);
    await vi.runAllTimersAsync();

    await expect(result).rejects.toThrow(`failure ${MAX_ATTEMPTS}`);
  });

  it.each([400, 401, 403, 404, 409])("doesn't retry a %i", async (status) => {
    const fetch = answering({ status }, { status: 200, body: {} });

    const result = call();
    await vi.runAllTimersAsync();

    expect((await result).status).toBe(status);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("sends a call that isn't repeatable once", async () => {
    const fetch = answering({ status: 503 }, { status: 200, body: {} });

    const result = call(false);
    await vi.runAllTimersAsync();

    expect((await result).status).toBe(503);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("gives each attempt its own timeout signal", async () => {
    const fetch = answering({ status: 503 }, { status: 200, body: {} });

    const result = call();
    await vi.runAllTimersAsync();
    await result;

    const signals = fetch.mock.calls.map(([, init]) => init.signal);
    expect(signals).toHaveLength(2);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(signals[0]).not.toBe(signals[1]);
  });
});
