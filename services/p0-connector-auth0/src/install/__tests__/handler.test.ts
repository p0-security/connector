import { ConnectorError, createLogger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAuth0,
  failing,
  newFakeAuth0,
  oauthFailing,
} from "../../__tests__/fake-auth0.ts";
import {
  ALLOWED_PATTERN,
  CLIENT_ID,
  CLIENT_SECRET,
  CREDENTIALS,
  TENANT,
} from "../../__tests__/fixtures.ts";
import { connectorError } from "../../__tests__/helpers.ts";
import { rateLimitRetry } from "../../auth0/api.ts";
import { REQUIRED_SCOPES } from "../../auth0/scopes.ts";
import { connectorRouter, t } from "../../router.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getClientSecret = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ getClientSecret }));

const requireAllowedDomains = vi.hoisted(() => vi.fn());
vi.mock("../../allowed-domains.ts", () => ({ requireAllowedDomains }));

const logger = createLogger();
logger.level = "silent";
const connector = t.createCallerFactory(connectorRouter)({ logger });
const validate = (input: unknown = CREDENTIALS) =>
  connector.auth0.install.validation.get(input as typeof CREDENTIALS);

let auth0: FakeAuth0;
let versions = 0;

beforeEach(() => {
  // A 429 is retried after a wait. These tests only care how it ends.
  rateLimitRetry.waitMs = 0;
  auth0 = newFakeAuth0({
    tenant: TENANT,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  vi.stubGlobal("fetch", auth0.fetch);
  getClientSecret.mockReset();
  getClientSecret.mockResolvedValue({
    secret: CLIENT_SECRET,
    version: `version-${++versions}`,
  });
  requireAllowedDomains.mockReset();
  requireAllowedDomains.mockReturnValue({
    pattern: ALLOWED_PATTERN,
    allows: () => true,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("install validation", () => {
  it("passes every step and reports the tenant and the allowed domains", async () => {
    await expect(validate()).resolves.toEqual({
      tenant: TENANT,
      allowedDomains: ALLOWED_PATTERN,
    });
  });

  it("refuses a tenant that isn't a canonical Auth0 domain, and calls nothing", async () => {
    const error = await validate({
      ...CREDENTIALS,
      tenant: "login.acme.com",
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(Error);
    expect(getClientSecret).not.toHaveBeenCalled();
    expect(auth0.calls).toEqual([]);
  });

  describe("the secret step", () => {
    it("fails naming the step when the secret can't be read, and asks Auth0 nothing", async () => {
      getClientSecret.mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "can't read it",
          payload: { secretId: "auth0-client-secret", manager: "aws" },
        })
      );

      const data = await connectorError(() => validate());

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: "can't read it",
        payload: {
          secretId: "auth0-client-secret",
          manager: "aws",
          step: "secret",
          tenant: TENANT,
        },
      });
      expect(auth0.calls).toEqual([]);
    });
  });

  describe("the authenticate step", () => {
    it("fails naming the step when the tenant refuses the credentials", async () => {
      getClientSecret.mockResolvedValue({ secret: "wrong", version: "v" });

      const data = await connectorError(() => validate());

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `Auth0 tenant ${TENANT} didn't accept the connector's client credentials (401): Unauthorized. Check the client id in the P0 install and the client secret in the connector's secret, and that the application is authorized for the Auth0 Management API.`,
        payload: {
          reason: "token_rejected",
          status: 401,
          step: "authenticate",
          tenant: TENANT,
        },
      });
    });

    it("passes on why the application isn't authorized for the Management API", async () => {
      auth0.intercept(() =>
        oauthFailing(
          403,
          "access_denied",
          'Client is not authorized to access "https://acme.us.auth0.com/api/v2/".'
        )
      );

      const data = await connectorError(() => validate());

      expect(data.message).toContain(
        'Client is not authorized to access "https://acme.us.auth0.com/api/v2/"'
      );
      expect(data.payload).toMatchObject({ step: "authenticate", status: 403 });
    });

    it("names the step on any other failure, such as a rate limit", async () => {
      auth0.intercept(() =>
        failing(429, "Too Many Requests", undefined, { "retry-after": "3" })
      );

      const data = await connectorError(() => validate());

      expect(data.type).toBe("rate_limited");
      expect(data.message).toBe(
        `Auth0 tenant ${TENANT} is rate limiting the connector. Retry in 3 seconds.`
      );
      expect(data.payload).toMatchObject({
        step: "authenticate",
        retryAfter: "3",
      });
    });

    it("names the step when the tenant can't be reached", async () => {
      auth0.intercept(() => ({ throws: new TypeError("fetch failed") }));

      const data = await connectorError(() => validate());

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toMatchObject({ step: "authenticate" });
    });
  });

  describe("the scopes step", () => {
    it("fails listing the one scope that's missing", async () => {
      auth0.state.scopes = REQUIRED_SCOPES.filter(
        (scope) => scope !== "read:roles"
      );

      const data = await connectorError(() => validate());

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `The connector's application on Auth0 tenant ${TENANT} is missing a Management API scope: read:roles. Authorize the application for the Management API with it, then validate again.`,
        payload: { missing: "read:roles", step: "scopes", tenant: TENANT },
      });
    });

    it("fails listing every scope that's missing, in order", async () => {
      auth0.state.scopes = ["read:users", "update:users"];

      const data = await connectorError(() => validate());

      const missing = REQUIRED_SCOPES.filter(
        (scope) => scope !== "read:users" && scope !== "update:users"
      );
      expect(data.message).toBe(
        `The connector's application on Auth0 tenant ${TENANT} is missing Management API scopes: ${missing.join(", ")}. Authorize the application for the Management API with them, then validate again.`
      );
      expect(data.payload).toMatchObject({ missing: missing.join(" ") });
    });

    it("fails when the token carries no scopes at all", async () => {
      auth0.state.scopes = [];

      const data = await connectorError(() => validate());

      expect(data.payload).toMatchObject({
        step: "scopes",
        missing: REQUIRED_SCOPES.join(" "),
      });
    });

    it("ignores extra scopes", async () => {
      auth0.state.scopes = [
        ...REQUIRED_SCOPES,
        "delete:users",
        "read:client_grants",
      ];

      await expect(validate()).resolves.toMatchObject({ tenant: TENANT });
    });

    // A cached token could be from before a scope was pulled.
    it("reads the scopes from a fresh exchange each time", async () => {
      await validate();
      auth0.state.scopes = ["read:users"];

      const data = await connectorError(() => validate());

      expect(data.payload).toMatchObject({ step: "scopes" });
    });
  });

  describe("the domains step", () => {
    it("fails naming the step when the pattern is unusable", async () => {
      requireAllowedDomains.mockImplementation(() => {
        throw new Error("DOMAIN_ALLOW_PATTERN isn't set, or is blank.");
      });

      const data = await connectorError(() => validate());

      expect(data).toEqual({
        type: "validation_error",
        message: "DOMAIN_ALLOW_PATTERN isn't set, or is blank.",
        payload: { step: "domains", tenant: TENANT },
      });
    });

    it("runs after the scopes", async () => {
      auth0.state.scopes = [];

      await connectorError(() => validate());

      expect(requireAllowedDomains).not.toHaveBeenCalled();
    });
  });
});
