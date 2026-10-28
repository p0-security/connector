/**
 * An OpenID provider double: the discovery document and the token endpoint's
 * `refresh_token` grant, as Google, Okta and Keycloak answer them. It accepts
 * the client by basic auth (form-encoded first, RFC 6749 2.3.1) or, when
 * `authMethods` leaves basic out, in the form.
 */
import { vi } from "vitest";

import { ADMIN_CREDENTIAL, ID_TOKEN } from "../../__tests__/fixtures.ts";

export const ISSUER = ADMIN_CREDENTIAL.issuer;
export const TOKEN_ENDPOINT = "https://oauth.idp.example.com/token";

export { ADMIN_CREDENTIAL, ID_TOKEN };

/** What must reach no error and no log line. */
export const PROVIDER_NEVER_SHOWN = [
  ADMIN_CREDENTIAL.clientSecret,
  ADMIN_CREDENTIAL.refreshToken,
  ID_TOKEN,
  "eyJTRU5USU5FTCI6MX0",
];

export type FakeProviderState = {
  /** `token_endpoint_auth_methods_supported`, absent when undefined. */
  authMethods?: string[];
  /** The discovery document's `issuer`. The issuer's own by default. */
  documentIssuer?: string;
  /** The discovery document's `token_endpoint`. */
  tokenEndpoint?: string;
  /** The refresh token the provider accepts. */
  refreshToken?: string;
  /** What a good refresh answers, instead of the ID token. */
  minted?: Record<string, unknown>;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const formEncode = (value: string) =>
  new URLSearchParams({ v: value }).toString().slice(2);

/**
 * The provider's answer to a call, or `undefined` for a URL that isn't the
 * provider's, for the caller to answer.
 */
export const answerAsProvider = (
  state: FakeProviderState,
  input: string,
  init: RequestInit = {}
): Response | undefined => {
  const method = init.method ?? "GET";
  const tokenEndpoint = state.tokenEndpoint ?? TOKEN_ENDPOINT;
  if (input === `${ISSUER}/.well-known/openid-configuration`) {
    if (method !== "GET") return json({ error: "method" }, 405);
    return json({
      issuer: state.documentIssuer ?? ISSUER,
      token_endpoint: tokenEndpoint,
      jwks_uri: `${ISSUER}/jwks`,
      ...(state.authMethods === undefined
        ? {}
        : { token_endpoint_auth_methods_supported: state.authMethods }),
    });
  }
  if (input === tokenEndpoint) {
    if (method !== "POST") return json({ error: "invalid_request" }, 405);
    const form = new URLSearchParams(
      typeof init.body === "string" ? init.body : ""
    );
    const basic = new Headers(init.headers).get("authorization");
    const { clientId, clientSecret, refreshToken } = ADMIN_CREDENTIAL;
    const methods = state.authMethods ?? ["client_secret_basic"];
    const byBasic =
      methods.includes("client_secret_basic") &&
      basic ===
        `Basic ${Buffer.from(`${formEncode(clientId)}:${formEncode(clientSecret)}`).toString("base64")}`;
    const byPost =
      methods.includes("client_secret_post") &&
      form.get("client_id") === clientId &&
      form.get("client_secret") === clientSecret;
    if (!byBasic && !byPost) return json({ error: "invalid_client" }, 401);
    if (form.get("grant_type") !== "refresh_token") {
      return json({ error: "unsupported_grant_type" }, 400);
    }
    if (form.get("refresh_token") !== (state.refreshToken ?? refreshToken)) {
      return json(
        {
          error: "invalid_grant",
          error_description: `Token has been expired or revoked: ${form.get("refresh_token")}`,
        },
        400
      );
    }
    return json(
      state.minted ?? {
        access_token: "SENTINEL-access-token",
        expires_in: 3599,
        id_token: ID_TOKEN,
        scope: "openid email",
        token_type: "Bearer",
      }
    );
  }
  return undefined;
};

/** Stubs `fetch` with the provider alone. */
export const newFakeProvider = (state: FakeProviderState = {}) => {
  const fetchMock = vi.fn(
    async (input: URL | string, init?: RequestInit) =>
      answerAsProvider(state, String(input), init) ??
      json({ error: "not found" }, 404)
  );
  vi.stubGlobal("fetch", fetchMock);
  return { state, fetch: fetchMock };
};

/**
 * Puts the provider in front of a Harbor double's stubbed `fetch`: the
 * provider answers its own URLs, and the double the rest.
 */
export const withProvider = <
  T extends {
    fetch: {
      getMockImplementation: () =>
        | ((url: string, init?: RequestInit) => Promise<Response>)
        | undefined;
      mockImplementation: (
        fn: (url: string, init?: RequestInit) => Promise<Response>
      ) => unknown;
    };
  },
>(
  harbor: T,
  state: FakeProviderState = {}
): T => {
  const fake = harbor.fetch.getMockImplementation();
  harbor.fetch.mockImplementation(
    async (url: string, init?: RequestInit) =>
      answerAsProvider(state, String(url), init) ??
      (fake ? fake(url, init) : json({ error: "no fake" }, 500))
  );
  return harbor;
};
