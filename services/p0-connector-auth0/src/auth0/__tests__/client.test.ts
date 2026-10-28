import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAuth0,
  TOKEN_LIFETIME_S,
  accessToken,
  failing,
  newFakeAuth0,
  oauthFailing,
} from "../../__tests__/fake-auth0.ts";
import {
  AWS_SECRET,
  CLIENT_ID,
  CLIENT_SECRET,
  CREDENTIALS,
  GCP_SECRET,
  TENANT,
} from "../../__tests__/fixtures.ts";
import { newRecordingLogger, thrown } from "../../__tests__/helpers.ts";
import type { ClientSecret, TenantCredentials } from "../../credentials.ts";
import type { ClientSecretValue } from "../../secrets.ts";
import { type TenantCall, auth0Request } from "../api.ts";
import { newAuth0Client } from "../client.ts";
import { TokenRejectedError } from "../errors.ts";
import { REQUIRED_SCOPES } from "../scopes.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getClientSecret = vi.hoisted(() =>
  vi.fn<(pointer: ClientSecret) => Promise<ClientSecretValue>>()
);
vi.mock("../../secrets.ts", () => ({ getClientSecret }));

const MINUTE = 60 * 1000;

let auth0: FakeAuth0;
let logs: ReturnType<typeof newRecordingLogger>;
let versions = 0;
/** The version the secret is at. A new one each test, so each starts without a cached token. */
let version: string;

const rotateSecret = () => {
  version = `version-${++versions}`;
};

const newClient = (identity: Partial<TenantCredentials> = {}) =>
  newAuth0Client({ ...CREDENTIALS, log: logs.log, ...identity });

/** A Management API read, which the fake answers with a 404 once the token checks out. */
const read = ({ log, tenant, accessToken }: TenantCall) =>
  auth0Request({
    log,
    tenant,
    method: "GET",
    path: "/api/v2/unserved",
    accessToken,
  });

/** One call to the connector that makes one Management API request, and whose 404 is the success case. */
const callOnce = async (client = newClient()) => {
  const error = await thrown(() => client.withToken(read));
  if ((error as { status?: number }).status !== 404) throw error;
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-15T09:00:00Z"));
  auth0 = newFakeAuth0({
    tenant: TENANT,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  vi.stubGlobal("fetch", auth0.fetch);
  logs = newRecordingLogger();
  rotateSecret();
  getClientSecret.mockReset();
  getClientSecret.mockImplementation(async () => ({
    secret: CLIENT_SECRET,
    version,
  }));
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("the token exchange", () => {
  it("asks the tenant for a client-credentials token for its Management API", async () => {
    await callOnce();

    const [exchange] = auth0.exchanges();
    expect(exchange?.url).toBe(`https://${TENANT}/oauth/token`);
    expect(exchange?.method).toBe("POST");
    expect(exchange?.body).toEqual({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: `https://${TENANT}/api/v2/`,
    });
    expect(exchange?.headers["content-type"]).toBe("application/json");
    expect(exchange?.headers.authorization).toBeUndefined();
  });

  it("sends the token it got on the Management API call, and nothing else as a bearer", async () => {
    await callOnce();

    expect(auth0.bearers()).toEqual([auth0.tokens[0]]);
  });

  it("never follows a redirect, which would resend the secret", async () => {
    await callOnce();

    expect(auth0.calls.map(({ redirect }) => redirect)).toEqual([
      "error",
      "error",
    ]);
  });

  it.each([
    [401, "access_denied", "Unauthorized"],
    [403, "access_denied", "Client is not authorized to access the API"],
    [400, "invalid_request", "Missing required parameter"],
  ])(
    "turns a %s into TokenRejectedError with Auth0's reason",
    async (status, code, description) => {
      auth0.intercept(() => oauthFailing(status, code, description));

      const error = await thrown(() => newClient().exchangeForScopes());

      expect(error).toBeInstanceOf(TokenRejectedError);
      expect(error).toMatchObject({ status, reason: description });
    }
  );

  it("refuses a wrong secret", async () => {
    getClientSecret.mockResolvedValue({ secret: "wrong", version });

    const error = await thrown(() => newClient().exchangeForScopes());

    expect(error).toMatchObject({ status: 401, reason: "Unauthorized" });
  });

  it("lets a 5xx through as an Auth0 failure, not as rejected credentials", async () => {
    auth0.intercept(() => failing(503));

    const error = await thrown(() => newClient().exchangeForScopes());

    expect(error).not.toBeInstanceOf(TokenRejectedError);
    expect(error).toMatchObject({ status: 503 });
  });

  it("fails as unknown when the token isn't fit to send", async () => {
    auth0.intercept(() => ({
      status: 200,
      body: { access_token: "bad\ntoken", expires_in: 60 },
    }));

    const error = await thrown(() => newClient().exchangeForScopes());

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("unknown");
  });
});

describe("the scopes", () => {
  it("are read from the token's own scope claim", async () => {
    await expect(newClient().exchangeForScopes()).resolves.toEqual([
      ...REQUIRED_SCOPES,
    ]);
  });

  it("come from the response when the token has no scope claim", async () => {
    auth0.intercept(() => ({
      status: 200,
      body: {
        access_token: "opaque-token",
        scope: "read:users read:roles",
        expires_in: 60,
      },
    }));

    await expect(newClient().exchangeForScopes()).resolves.toEqual([
      "read:users",
      "read:roles",
    ]);
  });

  it("prefer the claim to the response", async () => {
    auth0.intercept(() => ({
      status: 200,
      body: {
        access_token: accessToken({
          expiresAt: Date.now() + MINUTE * 60,
          scopes: ["read:users"],
        }),
        scope: "read:users read:roles",
      },
    }));

    await expect(newClient().exchangeForScopes()).resolves.toEqual([
      "read:users",
    ]);
  });

  it("are empty when neither says", async () => {
    auth0.intercept(() => ({
      status: 200,
      body: { access_token: "opaque-token" },
    }));

    await expect(newClient().exchangeForScopes()).resolves.toEqual([]);
  });

  // So validation can't be vouched for by a token issued before a scope was pulled.
  it("are always from a fresh exchange", async () => {
    await callOnce();
    auth0.state.scopes = ["read:users"];

    await expect(newClient().exchangeForScopes()).resolves.toEqual([
      "read:users",
    ]);
    expect(auth0.exchanges()).toHaveLength(2);
  });
});

describe("the secret", () => {
  it("is read by every call to the connector, even with a token cached", async () => {
    await callOnce();
    await callOnce();

    expect(getClientSecret).toHaveBeenCalledTimes(2);
    expect(getClientSecret).toHaveBeenCalledWith(AWS_SECRET);
    expect(auth0.exchanges()).toHaveLength(1);
  });

  it("is read once per call, however many requests the call makes", async () => {
    const client = newClient();

    await client.readSecret();
    await callOnce(client);
    await callOnce(client);

    expect(getClientSecret).toHaveBeenCalledTimes(1);
  });

  it("fails the call when it can't be read, and Auth0 isn't asked", async () => {
    const error = new Error("access denied");
    getClientSecret.mockRejectedValue(error);

    await expect(callOnce()).rejects.toBe(error);
    expect(auth0.calls).toEqual([]);
  });

  it("exchanges again once it's rotated", async () => {
    await callOnce();
    rotateSecret();
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
    expect(auth0.bearers()).toEqual(auth0.tokens);
  });
});

describe("the token cache", () => {
  it("reuses a token across calls", async () => {
    await callOnce();
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(1);
    expect(auth0.bearers()).toEqual([auth0.tokens[0], auth0.tokens[0]]);
  });

  it("keeps a token until five minutes before it expires", async () => {
    await callOnce();
    vi.setSystemTime(Date.now() + TOKEN_LIFETIME_S * 1000 - 5 * MINUTE - 1);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(1);
  });

  it("drops a token five minutes before it expires", async () => {
    await callOnce();
    vi.setSystemTime(Date.now() + TOKEN_LIFETIME_S * 1000 - 5 * MINUTE);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
  });

  it("keeps a token without exp until five minutes before its expires_in", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token"
        ? {
            status: 200,
            body: { access_token: "opaque-token", expires_in: 3600 },
          }
        : failing(404)
    );
    await callOnce();
    vi.setSystemTime(Date.now() + 55 * MINUTE - 1);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(1);
  });

  it("keeps a token per AWS region", async () => {
    await callOnce();
    await callOnce(
      newClient({ clientSecret: { ...AWS_SECRET, region: "eu-west-1" } })
    );

    expect(auth0.exchanges()).toHaveLength(2);
  });

  // The token's own expiry is what the tenant enforces.
  it("goes by the token's exp over expires_in when they differ", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token"
        ? {
            status: 200,
            body: {
              access_token: accessToken({
                expiresAt: Date.now() + 10 * MINUTE,
                scopes: [],
              }),
              expires_in: TOKEN_LIFETIME_S,
            },
          }
        : failing(404)
    );
    await callOnce();
    vi.setSystemTime(Date.now() + 5 * MINUTE);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
  });

  // Two Google pointers can name the same secret in different projects.
  it("keeps a token per Google project", async () => {
    await callOnce(newClient({ clientSecret: GCP_SECRET }));
    await callOnce(
      newClient({ clientSecret: { ...GCP_SECRET, projectId: "other-prod" } })
    );

    expect(auth0.exchanges()).toHaveLength(2);
  });

  // An exchange for an old version that fails late mustn't evict the one for
  // the version that replaced it.
  it("keeps a newer token when an older exchange fails after it", async () => {
    let failOld: (() => void) | undefined;
    const first = vi.fn<typeof fetch>(
      () =>
        new Promise((resolve) => {
          failOld = () =>
            resolve(new Response('{"error":"x"}', { status: 503 }));
        })
    );
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((resource, init) =>
        first.mock.calls.length === 0 &&
        (resource instanceof Request
          ? resource.url
          : resource.toString()
        ).endsWith("/oauth/token")
          ? first(resource, init)
          : auth0.fetch(resource, init)
      )
    );
    const old = callOnce();
    await vi.waitFor(() => expect(failOld).toBeDefined());
    rotateSecret();
    await callOnce();
    failOld?.();
    await expect(old).rejects.toMatchObject({ status: 503 });

    await callOnce();

    expect(auth0.exchanges()).toHaveLength(1);
  });

  it("uses expires_in when the token has no exp", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token"
        ? {
            status: 200,
            body: { access_token: "opaque-token", expires_in: 3600 },
          }
        : failing(404)
    );
    await callOnce();
    vi.setSystemTime(Date.now() + 55 * MINUTE - 1);
    await callOnce();
    vi.setSystemTime(Date.now() + 1);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
  });

  it("uses a token with neither for ten minutes", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token"
        ? { status: 200, body: { access_token: "opaque-token" } }
        : failing(404)
    );
    await callOnce();
    vi.setSystemTime(Date.now() + 10 * MINUTE - 1);
    await callOnce();
    vi.setSystemTime(Date.now() + 1);
    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
  });

  it("shares one exchange between calls that arrive together", async () => {
    await Promise.all([callOnce(), callOnce(), callOnce()]);

    expect(auth0.exchanges()).toHaveLength(1);
  });

  it("keeps a token per tenant, client and pointer", async () => {
    const other = newFakeAuth0({
      tenant: "other.eu.auth0.com",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((resource, init) =>
        new URL(
          resource instanceof Request ? resource.url : resource.toString()
        ).host === TENANT
          ? auth0.fetch(resource, init)
          : other.fetch(resource, init)
      )
    );

    await callOnce();
    await callOnce(newClient({ tenant: "other.eu.auth0.com" }));
    await callOnce(newClient({ clientSecret: GCP_SECRET }));
    // Another client of the same tenant, which this tenant doesn't know.
    await expect(
      callOnce(newClient({ clientId: "Other0123" }))
    ).rejects.toBeInstanceOf(TokenRejectedError);

    expect(auth0.exchanges()).toHaveLength(3);
    expect(other.exchanges()).toHaveLength(1);
  });

  it("forgets a failed exchange, so the next call tries again", async () => {
    auth0.intercept(() => failing(503));
    await expect(callOnce()).rejects.toMatchObject({ status: 503 });
    auth0.intercept(() => undefined);

    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
  });
});

describe("a 401 for a cached token", () => {
  it("is retried once with a new token", async () => {
    await callOnce();
    auth0.revokeTokens();

    await callOnce();

    expect(auth0.exchanges()).toHaveLength(2);
    expect(auth0.bearers()).toEqual([
      auth0.tokens[0],
      auth0.tokens[0],
      auth0.tokens[1],
    ]);
  });

  it("isn't retried for a token this call just exchanged", async () => {
    auth0.intercept((call) =>
      call.path === "/oauth/token" ? undefined : failing(401)
    );

    await expect(callOnce()).rejects.toMatchObject({ status: 401 });
    expect(auth0.exchanges()).toHaveLength(1);
    expect(auth0.apiCalls()).toHaveLength(1);
  });

  it("fails when the retry gets a 401 too", async () => {
    await callOnce();
    auth0.intercept((call) =>
      call.path === "/oauth/token" ? undefined : failing(401)
    );

    await expect(callOnce()).rejects.toMatchObject({ status: 401 });
    expect(auth0.apiCalls()).toHaveLength(3);
  });

  it("isn't retried for any other failure", async () => {
    await callOnce();
    auth0.intercept((call) =>
      call.path === "/oauth/token" ? undefined : failing(403)
    );

    await expect(callOnce()).rejects.toMatchObject({ status: 403 });
    expect(auth0.exchanges()).toHaveLength(1);
  });
});
