import type { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  HARBOR_HOST,
  connectorError,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import {
  MAX_ID_TOKEN_LENGTH,
  mintIdToken,
  parseTokenAnswer,
  parseTokenError,
} from "../oidc.ts";
import {
  ADMIN_CREDENTIAL,
  type FakeProviderState,
  ID_TOKEN,
  ISSUER,
  PROVIDER_NEVER_SHOWN,
  TOKEN_ENDPOINT,
  newFakeProvider,
} from "./fake-provider.ts";

type ConnectorErrorData = ConnectorError["data"];

const mint = () =>
  mintIdToken({ credential: ADMIN_CREDENTIAL, host: HARBOR_HOST, logger });

/** What the token endpoint was sent, as a form. */
const sentForm = (provider: ReturnType<typeof newFakeProvider>) => {
  const call = provider.fetch.mock.calls.find(
    ([url]) => String(url) === TOKEN_ENDPOINT
  );
  return {
    form: new URLSearchParams(
      typeof call?.[1]?.body === "string" ? call[1].body : ""
    ),
    headers: new Headers(call?.[1]?.headers),
    init: call?.[1],
  };
};

/** Answers every call with `response`. */
const answering = (response: () => Response) =>
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => response())
  );

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

let seen: ReturnType<typeof recordLogger>;

beforeEach(() => {
  seen = recordLogger();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

/**
 * A whole never-shown value, which every refusal below puts in what the
 * provider answers, so a check that it goes nowhere can fail.
 */
const LEAK = ADMIN_CREDENTIAL.refreshToken;

/** The failure's whole story, logs included, holds nothing secret. */
const expectNothingShown = (...others: unknown[]) => {
  const text = seen.seen(...others);
  expect(text).not.toContain(LEAK);
  for (const secret of PROVIDER_NEVER_SHOWN) expect(text).not.toContain(secret);
};

describe("mintIdToken", () => {
  it("mints an ID token from the refresh token, with the client by basic auth", async () => {
    const provider = newFakeProvider();
    await expect(mint()).resolves.toBe(ID_TOKEN);
    expect(provider.fetch.mock.calls.map(([url]) => String(url))).toEqual([
      `${ISSUER}/.well-known/openid-configuration`,
      TOKEN_ENDPOINT,
    ]);
    const { form, headers, init } = sentForm(provider);
    expect(Object.fromEntries(form)).toEqual({
      grant_type: "refresh_token",
      refresh_token: ADMIN_CREDENTIAL.refreshToken,
    });
    expect(headers.get("content-type")).toBe(
      "application/x-www-form-urlencoded"
    );
    expect(init?.redirect).toBe("manual");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expectNothingShown();
  });

  it("sends the client in the form when the provider takes only that", async () => {
    const provider = newFakeProvider({ authMethods: ["client_secret_post"] });
    await expect(mint()).resolves.toBe(ID_TOKEN);
    const { form, headers } = sentForm(provider);
    expect(form.get("client_id")).toBe(ADMIN_CREDENTIAL.clientId);
    expect(form.get("client_secret")).toBe(ADMIN_CREDENTIAL.clientSecret);
    expect(headers.get("authorization")).toBeNull();
  });

  it("prefers basic auth when the provider takes both", async () => {
    const provider = newFakeProvider({
      authMethods: ["client_secret_post", "client_secret_basic"],
    });
    await expect(mint()).resolves.toBe(ID_TOKEN);
    expect(sentForm(provider).form.get("client_secret")).toBeNull();
  });

  it("asks the issuer's discovery once, under a path when the issuer has one", async () => {
    const provider = newFakeProvider();
    await expect(
      mintIdToken({
        credential: { ...ADMIN_CREDENTIAL, issuer: `${ISSUER}/realms/p0` },
        host: HARBOR_HOST,
        logger,
      })
    ).rejects.toBeDefined();
    expect(String(provider.fetch.mock.calls[0]?.[0])).toBe(
      `${ISSUER}/realms/p0/.well-known/openid-configuration`
    );
  });

  it("says someone has to sign the admin account in again when the provider refuses the refresh token", async () => {
    newFakeProvider({ refreshToken: "a-different-one" });
    const error = await connectorError(mint);
    expect(error.data).toEqual({
      type: "validation_error",
      message: `The identity provider at idp.example.com refused the Harbor admin account's refresh token for ${HARBOR_HOST}: it has expired or been revoked. Someone has to sign the admin account in again and store the new refresh token in its secret.`,
      payload: {
        reason: "admin_signin_expired",
        host: HARBOR_HOST,
        provider: "idp.example.com",
        step: "token",
        status: 400,
      },
    });
    // The provider's `error_description` quotes the token. It goes nowhere.
    expectNothingShown(error);
  });

  it.each(["invalid_client", "unauthorized_client"])(
    "names the client as the problem on %s",
    async (code) => {
      answering(() =>
        json({ error: code, error_description: LEAK, echo: LEAK }, 401)
      );
      // Discovery would fail first on this answer: let it through.
      vi.mocked(fetch).mockImplementationOnce(async () =>
        json({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT })
      );
      const error = await connectorError(mint);
      expect(error.data.type).toBe("validation_error");
      expect(error.data.message).toContain(
        `rejected the client ID and secret in the Harbor admin credential's secret for ${HARBOR_HOST} (${code})`
      );
      expect(error.data.payload).toMatchObject({ code, status: 401 });
      expectNothingShown(error);
    }
  );

  it("fails on a wrong client when the provider answers by the fake's rules", async () => {
    newFakeProvider({ authMethods: ["client_secret_jwt"] });
    const error = await connectorError(mint);
    expect(error.data.payload).toMatchObject({ code: "invalid_client" });
  });

  describe.each<[string, Response, string, Record<string, unknown>]>([
    [
      "a 429",
      json({ error_description: LEAK }, 429),
      "rate_limited",
      { status: 429 },
    ],
    [
      "a 503",
      json({ error_description: LEAK }, 503),
      "upstream_unavailable",
      { status: 503 },
    ],
    [
      "a 400 with an OAuth code",
      json({ error: "invalid_scope", error_description: LEAK }, 400),
      "validation_error",
      { status: 400, code: "invalid_scope" },
    ],
    [
      "a 400 with a code that isn't OAuth's",
      json({ error: LEAK, error_description: LEAK }, 400),
      "validation_error",
      { status: 400 },
    ],
    [
      "a redirect",
      new Response(JSON.stringify({ echo: LEAK }), {
        status: 302,
        headers: { location: `https://elsewhere.example.com/?t=${LEAK}` },
      }),
      "validation_error",
      { status: 302 },
    ],
  ])("a token endpoint that answers %s", (_, response, type, payload) => {
    it(`fails as ${type}, quoting nothing the provider said but an OAuth code`, async () => {
      answering(() => response.clone());
      vi.mocked(fetch).mockImplementationOnce(async () =>
        json({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT })
      );
      const error = await connectorError(mint);
      expect(error.data.type).toBe(type);
      expect(error.data.payload).toEqual({
        host: HARBOR_HOST,
        provider: "idp.example.com",
        step: "token",
        ...payload,
      });
      expectNothingShown(error);
    });
  });

  it.each<[string, FakeProviderState]>([
    ["no ID token", { minted: { access_token: "x", token_type: "Bearer" } }],
    [
      "an ID token that isn't a JWS",
      { minted: { id_token: "SENTINEL\r\nX: y" } },
    ],
  ])(
    "says the refresh token needs the openid scope when the answer has %s",
    async (_, state) => {
      newFakeProvider(state);
      const error = await connectorError(mint);
      expect(error.data.type).toBe("validation_error");
      expect(error.data.message).toContain(
        "The refresh token has to be granted with the openid scope"
      );
      expect(error.data.message).not.toContain("SENTINEL");
    }
  );

  it("warns, without the token, when the provider rotates the refresh token", async () => {
    newFakeProvider({
      minted: { id_token: ID_TOKEN, refresh_token: "SENTINEL-rotated-9e1a" },
    });
    await expect(mint()).resolves.toBe(ID_TOKEN);
    expect(seen.lines()).toContainEqual([
      { provider: "idp.example.com" },
      "the identity provider rotated the admin account's refresh token; the stored one may stop working",
    ]);
    expect(seen.seen()).not.toContain("SENTINEL-rotated");
  });

  it("doesn't warn when the provider sends the same refresh token back", async () => {
    newFakeProvider({
      minted: {
        id_token: ID_TOKEN,
        refresh_token: ADMIN_CREDENTIAL.refreshToken,
      },
    });
    await expect(mint()).resolves.toBe(ID_TOKEN);
    expect(seen.seen()).not.toContain("rotated");
  });

  describe("discovery", () => {
    it.each<[string, FakeProviderState]>([
      ["names another issuer", { documentIssuer: "https://evil.example.com" }],
      [
        "names an http token endpoint",
        { tokenEndpoint: "http://oauth.idp.example.com/token" },
      ],
      [
        "names a token endpoint with a password",
        { tokenEndpoint: "https://u:p@oauth.idp.example.com/token" },
      ],
      ["names a token endpoint that isn't a URL", { tokenEndpoint: "token" }],
    ])(
      "refuses a document that %s, before the refresh token is sent",
      async (_, state) => {
        const provider = newFakeProvider(state);
        const error = await connectorError(mint);
        expect(error.data).toMatchObject({
          type: "validation_error",
          payload: { step: "discovery", provider: "idp.example.com" },
        });
        expect(error.data.message).toContain(
          "didn't answer as the OpenID provider the admin credential's secret names"
        );
        expect(provider.fetch).toHaveBeenCalledTimes(1);
      }
    );

    it("takes a document whose issuer has a trailing slash", async () => {
      newFakeProvider({ documentIssuer: `${ISSUER}/` });
      await expect(mint()).resolves.toBe(ID_TOKEN);
    });

    it.each([
      ["a 404", () => json({}, 404), 404],
      [
        "a redirect",
        () =>
          new Response(null, {
            status: 301,
            headers: { location: `${ISSUER}/x` },
          }),
        301,
      ],
      ["HTML", () => new Response("<html>SENTINEL</html>"), undefined],
      ["JSON of another shape", () => json({ token_endpoint: 7 }), undefined],
    ])("refuses %s, sending nothing further", async (_, response, status) => {
      answering(response);
      const error = await connectorError(mint);
      expect(error.data.payload).toEqual({
        host: HARBOR_HOST,
        provider: "idp.example.com",
        step: "discovery",
        ...(status === undefined ? {} : { status }),
      });
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("says the provider can't be reached, with Node's code only", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new TypeError("fetch failed", {
            cause: Object.assign(
              new Error(
                `getaddrinfo ENOTFOUND ${ADMIN_CREDENTIAL.refreshToken}`
              ),
              { code: "ENOTFOUND" }
            ),
          });
        })
      );
      const error = await connectorError(mint);
      expect(error.data).toEqual({
        type: "upstream_unavailable",
        message: `The connector couldn't reach the identity provider at idp.example.com to sign Harbor's admin account in for ${HARBOR_HOST}: ENOTFOUND. Check the issuer in the admin credential's secret, and try again.`,
        payload: {
          host: HARBOR_HOST,
          provider: "idp.example.com",
          step: "discovery",
        },
      });
      expectNothingShown(error);
    });

    it("says how long it waited when the provider doesn't answer in time", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new DOMException("timed out", "TimeoutError");
        })
      );
      const error = await connectorError(mint);
      expect(error.data.message).toContain("no answer within 10 seconds");
    });
  });
});

describe("the token endpoint's answers, as a property", () => {
  const seed = propertySeed();
  const random = seededRandom(seed);
  const pick = <T>(items: readonly T[]): T =>
    items[Math.floor(random() * items.length)] as T;

  const pieces = [
    "{",
    "}",
    "[",
    "]",
    ",",
    ":",
    '"id_token"',
    '"refresh_token"',
    '"error"',
    '"invalid_grant"',
    '"SENTINEL"',
    `"${ID_TOKEN}"`,
    '"a.b."',
    '"a.b.c\\n"',
    "null",
    "7",
    "true",
    '"x"',
    " ",
  ];

  const piece = () => {
    const parts: string[] = [];
    const size = Math.floor(random() * 12);
    for (let i = 0; i < size; i++) parts.push(pick(pieces));
    return parts.join("");
  };

  it(
    "never throws, and gives back nothing of the body but a token in JWS form or an OAuth code",
    { timeout: 30_000 },
    () => {
      for (let i = 0; i < 5000; i++) {
        // Half the cases are objects with the fields, to reach past the parse.
        const text =
          random() < 0.5
            ? piece()
            : JSON.stringify({
                id_token: pick([
                  ID_TOKEN,
                  "SENTINEL",
                  7,
                  null,
                  "a.b.c",
                  `${"a".repeat(MAX_ID_TOKEN_LENGTH)}.b.c`,
                ]),
                ...(random() < 0.5
                  ? { refresh_token: pick(["r", "SENTINEL", 1]) }
                  : {}),
                ...(random() < 0.5
                  ? { error: pick(["invalid_grant", "SENTINEL", 2]) }
                  : {}),
              });
        const where = `seed ${seed}, case ${JSON.stringify(text.slice(0, 200))}`;
        const answer = parseTokenAnswer(text, "r");
        if (answer.kind === "id_token") {
          expect(answer.idToken, where).toMatch(
            /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
          );
          expect(answer.idToken.length, where).toBeLessThanOrEqual(
            MAX_ID_TOKEN_LENGTH
          );
        }
        expect(
          JSON.stringify({ ...answer, idToken: undefined }),
          where
        ).not.toContain("SENTINEL");
        const code = parseTokenError(text);
        expect(
          code === undefined ||
            [
              "invalid_request",
              "invalid_client",
              "invalid_grant",
              "unauthorized_client",
              "unsupported_grant_type",
              "invalid_scope",
            ].includes(code),
          where
        ).toBe(true);
      }
    }
  );

  it("reads a body that isn't there as no code", () => {
    expect(parseTokenError(undefined)).toBeUndefined();
  });
});

describe("parseTokenAnswer, case by case", () => {
  it.each(["not JSON", "[]", "null"])("reads %j as not JSON", (text) => {
    expect(parseTokenAnswer(text, "r")).toEqual({ kind: "not_json" });
  });

  it("reads JSON without an ID token as no ID token", () => {
    expect(
      parseTokenAnswer(JSON.stringify({ access_token: "x" }), "r")
    ).toEqual({ kind: "no_id_token" });
  });

  it("doesn't call a refresh token rotated when the answer has none", () => {
    expect(
      parseTokenAnswer(JSON.stringify({ id_token: ID_TOKEN }), "r")
    ).toEqual({ kind: "id_token", idToken: ID_TOKEN, rotated: false });
  });

  it("takes an ID token exactly as long as the cap", () => {
    const idToken = `${"a".repeat(MAX_ID_TOKEN_LENGTH - 4)}.b.c`;
    expect(idToken).toHaveLength(MAX_ID_TOKEN_LENGTH);
    expect(
      parseTokenAnswer(JSON.stringify({ id_token: idToken }), "r")
    ).toEqual({ kind: "id_token", idToken, rotated: false });
  });
});

describe("mintIdToken, message by message", () => {
  const PROVIDER = "idp.example.com";
  const BASE = { host: HARBOR_HOST, provider: PROVIDER };

  /** Discovery answers as the provider does, and the token endpoint with `response`. */
  const tokenAnswers = (response: () => Response) => {
    answering(response);
    vi.mocked(fetch).mockImplementationOnce(async () =>
      json({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT })
    );
  };

  const NOT_A_PROVIDER = `${PROVIDER} didn't answer as the OpenID provider the admin credential's secret names`;
  const CHECK_ISSUER =
    "Check that the secret's issuer is the issuer Harbor's OIDC settings use.";

  it("asks for discovery with a GET for JSON, and the token endpoint for JSON", async () => {
    const provider = newFakeProvider();
    await expect(mint()).resolves.toBe(ID_TOKEN);
    const discovery = provider.fetch.mock.calls[0]?.[1];
    expect(discovery?.method).toBe("GET");
    expect(new Headers(discovery?.headers).get("accept")).toBe(
      "application/json"
    );
    expect(sentForm(provider).headers.get("accept")).toBe("application/json");
  });

  it("names the status discovery answered", async () => {
    answering(() => json({}, 404));
    const error = await connectorError(mint);
    expect(error.data).toStrictEqual({
      type: "validation_error",
      message: `${NOT_A_PROVIDER}: it answered 404. ${CHECK_ISSUER}`,
      payload: { ...BASE, step: "discovery", status: 404 },
    });
  });

  it("names no status when discovery's answer isn't a document", async () => {
    answering(() => new Response("<html></html>"));
    const error = await connectorError(mint);
    expect(error.data).toStrictEqual({
      type: "validation_error",
      message: `${NOT_A_PROVIDER}. ${CHECK_ISSUER}`,
      payload: { ...BASE, step: "discovery" },
    });
  });

  it("refuses a discovery answer of 300", async () => {
    answering(
      () =>
        new Response(JSON.stringify({ issuer: ISSUER }), {
          status: 300,
        })
    );
    const error = await connectorError(mint);
    expect(error.data.payload).toEqual({
      ...BASE,
      step: "discovery",
      status: 300,
    });
  });

  it("takes a document whose issuer has several trailing slashes", async () => {
    newFakeProvider({ documentIssuer: `${ISSUER}//` });
    await expect(mint()).resolves.toBe(ID_TOKEN);
  });

  it.each([
    ["a username alone", "https://u@oauth.idp.example.com/token"],
    ["a password alone", "https://:p@oauth.idp.example.com/token"],
  ])(
    "refuses a token endpoint with %s, before the refresh token is sent",
    async (_, tokenEndpoint) => {
      const provider = newFakeProvider({ tokenEndpoint });
      const error = await connectorError(mint);
      expect(error.data.message).toContain(NOT_A_PROVIDER);
      expect(provider.fetch).toHaveBeenCalledTimes(1);
    }
  );

  it.each<[string, Error, string]>([
    [
      "Node's code on the error itself",
      Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" }),
      "ECONNRESET",
    ],
    ["nothing about itself", new Error("boom"), "the request failed"],
  ])(
    "says the provider can't be reached when the failure carries %s",
    async (_, failure, reason) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw failure;
        })
      );
      const error = await connectorError(mint);
      expect(error.data.message).toBe(
        `The connector couldn't reach the identity provider at ${PROVIDER} to sign Harbor's admin account in for ${HARBOR_HOST}: ${reason}. Check the issuer in the admin credential's secret, and try again.`
      );
    }
  );

  it("says the token step failed when only the token endpoint can't be reached", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: URL | string) => {
        if (String(url) === TOKEN_ENDPOINT) throw new Error("boom");
        return json({ issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT });
      })
    );
    const error = await connectorError(mint);
    expect(error.data).toMatchObject({
      type: "upstream_unavailable",
      payload: { ...BASE, step: "token" },
    });
  });

  it.each<[string, () => Response, ConnectorErrorData]>([
    [
      "a 300",
      () =>
        new Response(JSON.stringify({ id_token: ID_TOKEN }), { status: 300 }),
      {
        type: "validation_error",
        message: `The identity provider at ${PROVIDER} refused to sign Harbor's admin account in for ${HARBOR_HOST}: it answered 300. Check the admin credential's secret.`,
        payload: { ...BASE, step: "token", status: 300 },
      },
    ],
    [
      "a 400 with an OAuth code",
      () => json({ error: "invalid_scope" }, 400),
      {
        type: "validation_error",
        message: `The identity provider at ${PROVIDER} refused to sign Harbor's admin account in for ${HARBOR_HOST}: it answered 400 (invalid_scope). Check the admin credential's secret.`,
        payload: { ...BASE, step: "token", status: 400, code: "invalid_scope" },
      },
    ],
    [
      "a 429",
      () => json({}, 429),
      {
        type: "rate_limited",
        message: `The identity provider at ${PROVIDER} is limiting the connector's calls: it answered 429. Try again later.`,
        payload: { ...BASE, step: "token", status: 429 },
      },
    ],
    [
      "a 500",
      () => json({}, 500),
      {
        type: "upstream_unavailable",
        message: `The identity provider at ${PROVIDER} answered 500 when the connector asked it to sign Harbor's admin account in for ${HARBOR_HOST}. Try again later.`,
        payload: { ...BASE, step: "token", status: 500 },
      },
    ],
    [
      "invalid_client",
      () => json({ error: "invalid_client" }, 401),
      {
        type: "validation_error",
        message: `The identity provider at ${PROVIDER} rejected the client ID and secret in the Harbor admin credential's secret for ${HARBOR_HOST} (invalid_client). Check that they are Harbor's OIDC client's ID and a current secret for it.`,
        payload: {
          ...BASE,
          step: "token",
          status: 401,
          code: "invalid_client",
        },
      },
    ],
    [
      "a 200 that isn't JSON",
      () => new Response("<html></html>"),
      {
        type: "validation_error",
        message: `The identity provider at ${PROVIDER} didn't return an ID token for Harbor's admin account on ${HARBOR_HOST}. The refresh token has to be granted with the openid scope: sign the admin account in again with the openid and email scopes, and store the new refresh token in its secret.`,
        payload: { ...BASE, step: "token", answer: "not_json" },
      },
    ],
    [
      "a 200 without an ID token",
      () => json({ access_token: "x" }),
      {
        type: "validation_error",
        message: `The identity provider at ${PROVIDER} didn't return an ID token for Harbor's admin account on ${HARBOR_HOST}. The refresh token has to be granted with the openid scope: sign the admin account in again with the openid and email scopes, and store the new refresh token in its secret.`,
        payload: { ...BASE, step: "token", answer: "no_id_token" },
      },
    ],
  ])(
    "fails a token endpoint's %s with its own message",
    async (_, response, data) => {
      tokenAnswers(response);
      const error = await connectorError(mint);
      expect(error.data).toStrictEqual(data);
    }
  );
});
