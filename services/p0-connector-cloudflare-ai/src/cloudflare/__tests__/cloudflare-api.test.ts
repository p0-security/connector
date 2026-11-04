import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_ID,
  NEVER_SHOWN,
  TOKEN,
  connectorError,
  logger,
  recordLogger,
} from "../../__tests__/fixtures.ts";
import {
  CLOUDFLARE_API,
  MAX_PAGES,
  newCloudflareApi,
  newCloudflareClient,
} from "../cloudflare-api.ts";
import { TOKEN_CAP_MESSAGE, toConnectorError } from "../errors.ts";
import { answer, failed, ok, stubCloudflare } from "./fake-cloudflare.ts";

const ACCOUNT = `/accounts/${ACCOUNT_ID}`;

const client = () =>
  newCloudflareClient(newCloudflareApi({ logger, token: TOKEN }), ACCOUNT_ID);

/** The `ConnectorError` a client call fails with, after mapping. */
const mapped = (run: () => Promise<unknown>) =>
  connectorError(() =>
    run().catch((error: unknown) => {
      throw toConnectorError(error);
    })
  );

const SPEC = {
  expiresOn: "2026-11-04T18:00:00Z",
  name: "P0 p0/access-token/cloudflare/prod/abc",
  policies: [
    {
      effect: "allow" as const,
      permission_groups: [{ id: "group-1" }],
      resources: { [`com.cloudflare.api.account.${ACCOUNT_ID}`]: "*" as const },
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("calls", () => {
  it("sends the install token to the fixed host only, and follows no redirect", async () => {
    const cloudflare = stubCloudflare({
      [`GET ${ACCOUNT}/tokens/verify`]: () =>
        ok({ id: "tok-1", status: "active" }),
    });

    await expect(client().verifyToken()).resolves.toEqual({
      id: "tok-1",
      status: "active",
    });

    const [url, init] = cloudflare.fetch.mock.calls[0] ?? [];
    expect(url).toBe(`${CLOUDFLARE_API}${ACCOUNT}/tokens/verify`);
    expect(init).toMatchObject({
      headers: { Authorization: `Bearer ${TOKEN}` },
      method: "GET",
      redirect: "manual",
    });
  });

  it("mints a token with its name, policies and expiry", async () => {
    const cloudflare = stubCloudflare({
      [`POST ${ACCOUNT}/tokens`]: () =>
        ok({ id: "tok-2", name: SPEC.name, value: "grant-value" }),
    });

    await expect(client().createToken(SPEC)).resolves.toEqual({
      id: "tok-2",
      value: "grant-value",
    });
    expect(cloudflare.body(0)).toEqual({
      expires_on: SPEC.expiresOn,
      name: SPEC.name,
      policies: SPEC.policies,
    });
  });

  // The body V1 tested a live group change with.
  it("PUTs the whole token, active", async () => {
    const cloudflare = stubCloudflare({
      [`PUT ${ACCOUNT}/tokens/tok-2`]: () => ok({ id: "tok-2" }),
    });

    await client().updateToken("tok-2", SPEC);

    expect(cloudflare.body(0)).toEqual({
      expires_on: SPEC.expiresOn,
      name: SPEC.name,
      policies: SPEC.policies,
      status: "active",
    });
  });

  it("deletes a token by id", async () => {
    const cloudflare = stubCloudflare({
      [`DELETE ${ACCOUNT}/tokens/tok-2`]: () => ok({ id: "tok-2" }),
    });

    await client().deleteToken("tok-2");

    expect(cloudflare.calls()).toEqual([
      `DELETE ${CLOUDFLARE_API}${ACCOUNT}/tokens/tok-2`,
    ]);
  });

  it("encodes an id as one path segment", async () => {
    const cloudflare = stubCloudflare({
      [`GET ${ACCOUNT}/tokens/a%2F..%2Fb`]: () =>
        ok({ id: "x", name: "x", policies: [], status: "active" }),
    });

    await client().getToken("a/../b");

    expect(cloudflare.fetch).toHaveBeenCalledOnce();
  });

  it("lists the permission groups in one call", async () => {
    const group = {
      id: "c8fed203ed3043cba015a93ad1616f1f",
      is_selectable: true,
      name: "Zone Read",
      scopes: ["com.cloudflare.api.account.zone"],
    };
    stubCloudflare({
      [`GET ${ACCOUNT}/tokens/permission_groups`]: () => ok([group]),
    });

    await expect(client().listPermissionGroups()).resolves.toEqual([group]);
  });
});

describe("paging", () => {
  const zones = (page: number) =>
    [1, 2].map((n) => ({ id: `z-${page}-${n}`, name: `${page}-${n}.example` }));

  it("reads every page of zones, 50 to a page, on the account", async () => {
    const cloudflare = stubCloudflare({
      "GET /zones": (url) => {
        const page = Number(url.searchParams.get("page"));
        return ok(zones(page), { page, total_pages: 3 });
      },
    });

    const listed = await client().listZones();

    expect(listed.map(({ id }) => id)).toEqual([
      "z-1-1",
      "z-1-2",
      "z-2-1",
      "z-2-2",
      "z-3-1",
      "z-3-2",
    ]);
    expect(cloudflare.calls()).toEqual(
      [1, 2, 3].map(
        (page) =>
          `GET ${CLOUDFLARE_API}/zones?account.id=${ACCOUNT_ID}&page=${page}&per_page=50`
      )
    );
  });

  it("reads every page of the account's tokens", async () => {
    const cloudflare = stubCloudflare({
      [`GET ${ACCOUNT}/tokens`]: (url) => {
        const page = Number(url.searchParams.get("page"));
        return ok([{ id: `tok-${page}`, name: "P0 x", status: "active" }], {
          page,
          total_pages: 2,
        });
      },
    });

    await expect(client().listTokens()).resolves.toEqual([
      { id: "tok-1", name: "P0 x", status: "active" },
      { id: "tok-2", name: "P0 x", status: "active" },
    ]);
    expect(cloudflare.fetch).toHaveBeenCalledTimes(2);
  });

  it("stops at an empty page, whatever total_pages says", async () => {
    const cloudflare = stubCloudflare({
      "GET /zones": (url) => {
        const page = Number(url.searchParams.get("page"));
        return ok(page === 1 ? zones(1) : [], { page, total_pages: 9 });
      },
    });

    await expect(client().listZones()).resolves.toHaveLength(2);
    expect(cloudflare.fetch).toHaveBeenCalledTimes(2);
  });

  it("gives up after the most pages it reads", async () => {
    const cloudflare = stubCloudflare({
      "GET /zones": (url) =>
        ok(zones(1), {
          page: Number(url.searchParams.get("page")),
          total_pages: MAX_PAGES + 1,
        }),
    });

    const { data } = await mapped(() => client().listZones());

    expect(data).toMatchObject({
      payload: { reason: "endless" },
      type: "unknown",
    });
    expect(cloudflare.fetch).toHaveBeenCalledTimes(MAX_PAGES);
  });

  it("refuses a page without result_info", async () => {
    stubCloudflare({ "GET /zones": () => ok(zones(1)) });

    const { data } = await mapped(() => client().listZones());

    expect(data).toMatchObject({
      payload: { reason: "wrong_shape" },
      type: "unknown",
    });
  });
});

describe("error mapping", () => {
  const verify = () => client().verifyToken();
  const ROUTE = "GET /accounts/{account_id}/tokens/verify";

  it.each([
    [
      401,
      "insufficient_privileges",
      `Cloudflare didn't accept the connector's install token on ${ROUTE} (401). Check that the token in the secret is current and active, and that its IP filter, if any, allows the connector.`,
    ],
    [
      403,
      "insufficient_privileges",
      `Cloudflare refused ${ROUTE} with 403: the install token's permission groups don't allow it.`,
    ],
    [
      404,
      "object_not_found",
      `Cloudflare found nothing for ${ROUTE} (404). Check the account ID on the Cloudflare account in P0, and that the token belongs to that account.`,
    ],
    [400, "validation_error", `Cloudflare refused ${ROUTE} with 400.`],
    [
      429,
      "rate_limited",
      `Cloudflare is limiting the account's API calls: it answered ${ROUTE} with 429. Try again in five minutes.`,
    ],
    [
      503,
      "upstream_unavailable",
      `Cloudflare answered ${ROUTE} with 503. Try again later.`,
    ],
    [
      418,
      "validation_error",
      `Cloudflare answered ${ROUTE} with 418, which the connector doesn't expect. Contact P0 support if it keeps happening.`,
    ],
  ] as const)(
    "maps %i to %s, with Cloudflare's codes and not its message",
    async (status, type, message) => {
      stubCloudflare({
        [`GET ${ACCOUNT}/tokens/verify`]: () =>
          failed(status, [{ code: 9109, message: `echo ${TOKEN}` }]),
      });

      const { data } = await mapped(verify);

      expect(data).toEqual({
        message,
        payload: { codes: "9109", status },
        type,
      });
    }
  );

  it("maps a redirect to validation_error, without reading on", async () => {
    stubCloudflare({
      [`GET ${ACCOUNT}/tokens/verify`]: () =>
        new Response(null, {
          headers: { Location: "https://elsewhere.example" },
          status: 302,
        }),
    });

    const { data } = await mapped(verify);

    expect(data).toEqual({
      message: `Cloudflare answered ${ROUTE} with a redirect (302), which the connector doesn't follow. Contact P0 support if it keeps happening.`,
      payload: { status: 302 },
      type: "validation_error",
    });
  });

  it("maps a 2xx with success: false as its status", async () => {
    stubCloudflare({
      [`GET ${ACCOUNT}/tokens/verify`]: () =>
        answer(200, {
          errors: [{ code: 1000, message: "nope" }],
          result: null,
          success: false,
        }),
    });

    const { data } = await mapped(verify);

    expect(data).toMatchObject({
      payload: { codes: "1000", status: 200 },
      type: "validation_error",
    });
  });

  it.each([
    ["not JSON", () => new Response("<html>", { status: 200 }), "not_json"],
    ["the wrong shape", () => ok({ status: "active" }), "wrong_shape"],
  ] as const)(
    "maps a 2xx that is %s to unknown",
    async (_case, respond, reason) => {
      stubCloudflare({ [`GET ${ACCOUNT}/tokens/verify`]: respond });

      const { data } = await mapped(verify);

      expect(data).toMatchObject({ payload: { reason }, type: "unknown" });
    }
  );

  it("maps no answer to upstream_unavailable, with Node's code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(
        new TypeError("fetch failed", {
          cause: Object.assign(new Error(`getaddrinfo ${TOKEN}`), {
            code: "ENOTFOUND",
          }),
        })
      )
    );

    const { data } = await mapped(verify);

    expect(data).toEqual({
      message:
        "The connector couldn't reach Cloudflare: ENOTFOUND. Check that the connector's network can reach api.cloudflare.com, and try again.",
      payload: { code: "ENOTFOUND" },
      type: "upstream_unavailable",
    });
  });

  it("maps a timeout to upstream_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockRejectedValue(
          new DOMException("The operation timed out.", "TimeoutError")
        )
    );

    const { data } = await mapped(verify);

    expect(data.message).toBe(
      "The connector couldn't reach Cloudflare: no answer within 10 seconds. Check that the connector's network can reach api.cloudflare.com, and try again."
    );
  });

  it("passes on what isn't a Cloudflare failure", () => {
    const bug = new Error("a bug");
    expect(toConnectorError(bug)).toBe(bug);
  });

  it("shows neither the token nor Cloudflare's message, however a call fails", async () => {
    for (const respond of [
      () => failed(401, [{ code: 9109, message: `bad ${TOKEN}` }]),
      () => failed(500, [{ code: 10000, message: `bad ${TOKEN}` }]),
      () => new Response(`{"echo":"${TOKEN}"`, { status: 200 }),
    ]) {
      const log = recordLogger();
      stubCloudflare({ [`GET ${ACCOUNT}/tokens/verify`]: respond });

      const error = await mapped(verify);

      expect(error).toBeInstanceOf(ConnectorError);
      const seen = log.seen(error, JSON.stringify(error.data));
      for (const marker of [...NEVER_SHOWN, "bad "]) {
        expect(seen).not.toContain(marker);
      }
      vi.restoreAllMocks();
    }
  });
});

// Cloudflare documents no code or text for the 500-token cap, and V1
// couldn't make one, so these bodies stand in for it (spec section 8).
describe("the token cap", () => {
  const CAP_ERRORS = [
    {
      code: 1001,
      message: "You have reached the maximum number of API tokens",
    },
  ];

  it.each([400, 403, 409])(
    "maps a mint's %i that names a limit to the cap's validation_error",
    async (status) => {
      stubCloudflare({
        [`POST ${ACCOUNT}/tokens`]: () => failed(status, CAP_ERRORS),
      });

      const { data } = await mapped(() => client().createToken(SPEC));

      expect(data).toEqual({
        message: TOKEN_CAP_MESSAGE,
        payload: { codes: "1001", status },
        type: "validation_error",
      });
    }
  );

  it("keeps a mint's 429 the rate limit", async () => {
    stubCloudflare({
      [`POST ${ACCOUNT}/tokens`]: () =>
        failed(429, [{ code: 971, message: "Rate limit exceeded" }]),
    });

    const { data } = await mapped(() => client().createToken(SPEC));

    expect(data.type).toBe("rate_limited");
  });

  it("keeps a mint's other 400 a plain refusal", async () => {
    stubCloudflare({
      [`POST ${ACCOUNT}/tokens`]: () =>
        failed(400, [{ code: 400, message: "Invalid policy" }]),
    });

    const { data } = await mapped(() => client().createToken(SPEC));

    expect(data.message).not.toBe(TOKEN_CAP_MESSAGE);
  });

  it("reads a limit on any other call as that call's failure", async () => {
    stubCloudflare({
      [`PUT ${ACCOUNT}/tokens/tok-2`]: () => failed(400, CAP_ERRORS),
    });

    const { data } = await mapped(() => client().updateToken("tok-2", SPEC));

    expect(data.message).not.toBe(TOKEN_CAP_MESSAGE);
  });
});
