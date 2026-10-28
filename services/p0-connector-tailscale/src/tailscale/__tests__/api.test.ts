import { afterEach, describe, expect, it, vi } from "vitest";

import { newRecordingLogger, thrown } from "../../__tests__/helpers.ts";
import {
  TailscaleError,
  segment,
  tailnetSegment,
  tailscaleRequest,
  withoutSecrets,
} from "../api.ts";

const { log } = newRecordingLogger();

afterEach(() => {
  vi.unstubAllGlobals();
});

const stub = (response: Response) => {
  const fetch = vi.fn(async () => response);
  vi.stubGlobal("fetch", fetch);
  return fetch;
};

describe("tailscaleRequest", () => {
  it("calls only api.tailscale.com, with no redirects", async () => {
    const fetch = stub(new Response("{}", { status: 200 }));

    await tailscaleRequest({
      log,
      method: "PATCH",
      path: "/api/v2/tailnet/T1/device-attributes",
      accessToken: "tskey-api-1",
      body: { json: {} },
    });

    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(
      "https://api.tailscale.com/api/v2/tailnet/T1/device-attributes"
    );
    expect(init.redirect).toBe("error");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      Authorization: "Bearer tskey-api-1",
      "Content-Type": "application/json",
    });
  });

  it("reads Tailscale's message and cuts the token out of it", async () => {
    stub(
      new Response(JSON.stringify({ message: "bad tskey-api-1 here" }), {
        status: 400,
      })
    );

    const error = await thrown(() =>
      tailscaleRequest({
        log,
        method: "GET",
        path: "/x",
        accessToken: "tskey-api-1",
      })
    );

    expect(error).toBeInstanceOf(TailscaleError);
    expect((error as TailscaleError).tailscaleMessage).toBe(
      "bad [redacted] here"
    );
  });

  it("takes Retry-After on a 429", async () => {
    stub(
      new Response(JSON.stringify({ message: "too many requests" }), {
        status: 429,
        headers: { "retry-after": "12" },
      })
    );

    const error = await thrown(() =>
      tailscaleRequest({ log, method: "GET", path: "/x" })
    );

    expect((error as TailscaleError).retryAfter).toBe("12");
  });
});

describe("withoutSecrets", () => {
  it("caps a long message", () => {
    expect(withoutSecrets("x".repeat(600), []).length).toBe(503);
  });
});

describe("segment", () => {
  it.each(["", ".", ".."])("refuses %j", (value) => {
    expect(() => segment(value)).toThrow();
  });

  it("encodes a legacy tailnet id", () => {
    expect(tailnetSegment("alice@gmail.com")).toBe("alice%40gmail.com");
  });

  it("refuses a tailnet with a slash", () => {
    expect(() => tailnetSegment("T1/../x")).toThrow();
  });
});
