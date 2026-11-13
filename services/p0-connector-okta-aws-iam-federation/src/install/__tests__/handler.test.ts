import { createPublicKey, verify } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_ID,
  APP_INPUT,
  CLIENT_ID,
  DOMAIN,
  JWK,
  KEYS,
  answer,
  connectorError,
  logger,
  stubOkta,
} from "../../__tests__/fixtures.ts";
import { connectorRouter } from "../../router.ts";
import { readPrivateKey } from "../../secrets.ts";

vi.mock("../../secrets.ts");

const APP_PATH = `/api/v1/apps/${APP_ID}`;
const ENTITY_ID = "http://www.okta.com/exk1aws2federation3";
const METADATA = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="${ENTITY_ID}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`;

const AWS_APP = {
  id: APP_ID,
  name: "amazon_aws",
  label: "AWS Production",
  status: "ACTIVE",
  signOnMode: "SAML_2_0",
  settings: { app: { awsEnvironmentType: "aws.amazon", joinAllRoles: false } },
  visibility: { hide: { iOS: false } },
};

const token = () => answer(200, { access_token: "at", token_type: "Bearer" });

const oktaWith = ({
  app = AWS_APP,
  metadata = METADATA,
}: { app?: object; metadata?: string } = {}) =>
  stubOkta({
    "POST /oauth2/v1/token": token,
    [`GET ${APP_PATH}`]: () => answer(200, app),
    [`GET ${APP_PATH}/sso/saml/metadata`]: () => new Response(metadata),
    [`POST /api/v1/meta/schemas/apps/${APP_ID}/default`]: () => answer(200, {}),
    [`PUT ${APP_PATH}`]: () => answer(200, app),
  });

const caller = () =>
  connectorRouter.createCaller({ logger })["okta-aws-iam-federation"].install;

const validate = () => caller().validation.get(APP_INPUT);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readPrivateKey).mockResolvedValue({
    key: KEYS.privateKey,
    kid: JWK.kid,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("install validation", () => {
  it("returns the app's label and entity ID, reading only", async () => {
    const okta = oktaWith();

    await expect(validate()).resolves.toEqual({
      entityId: ENTITY_ID,
      label: "AWS Production",
    });
    expect(okta.calls()).toEqual([
      "POST /oauth2/v1/token",
      `GET ${APP_PATH}`,
      `GET ${APP_PATH}/sso/saml/metadata`,
    ]);
  });

  it("asks for a token with a client assertion signed by the private key", async () => {
    const okta = oktaWith();

    await validate();

    const body = new URLSearchParams(
      okta.fetch.mock.calls[0]?.[1]?.body as string
    );
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("scope")).toBe(
      "okta.apps.manage okta.schemas.manage okta.users.read"
    );
    const [header, payload, signature] = body
      .get("client_assertion")!
      .split(".");
    const decode = (part: string) =>
      JSON.parse(Buffer.from(part, "base64url").toString());
    expect(decode(header)).toEqual({ alg: "RS256", kid: "key-1", typ: "JWT" });
    expect(decode(payload)).toMatchObject({
      aud: `https://${DOMAIN}/oauth2/v1/token`,
      iss: CLIENT_ID,
      sub: CLIENT_ID,
    });
    expect(
      verify(
        "RSA-SHA256",
        Buffer.from(`${header}.${payload}`),
        createPublicKey(KEYS.privateKey),
        Buffer.from(signature, "base64url")
      )
    ).toBe(true);
  });

  it("sends a call again after a 429, with a new client assertion", async () => {
    vi.useFakeTimers();
    let tokens = 0;
    const okta = stubOkta({
      "POST /oauth2/v1/token": () =>
        ++tokens === 1 ? answer(429, {}) : token(),
      [`GET ${APP_PATH}`]: () => answer(200, AWS_APP),
      [`GET ${APP_PATH}/sso/saml/metadata`]: () => new Response(METADATA),
    });

    const result = validate();
    await vi.runAllTimersAsync();

    await expect(result).resolves.toMatchObject({ entityId: ENTITY_ID });
    const assertions = okta.fetch.mock.calls
      .slice(0, 2)
      .map(([, init]) =>
        new URLSearchParams(init?.body as string).get("client_assertion")
      );
    expect(assertions[0]).not.toBe(assertions[1]);
    vi.useRealTimers();
  });

  it.each([
    ["invalid_client", "insufficient_privileges"],
    ["invalid_scope", "insufficient_privileges"],
    ["invalid_dpop_proof", "validation_error"],
  ])("fails at `token` when Okta answers %s", async (code, type) => {
    stubOkta({ "POST /oauth2/v1/token": () => answer(400, { error: code }) });

    const error = await connectorError(validate);

    expect(error.data).toMatchObject({
      payload: { code, step: "token" },
      type,
    });
  });

  it("fails at `secret` when the key can't be read", async () => {
    const { ConnectorError } = await import("@p0security/connector-core");
    vi.mocked(readPrivateKey).mockRejectedValue(
      new ConnectorError({
        message: "missing",
        payload: { manager: "aws" },
        type: "object_not_found",
      })
    );

    const error = await connectorError(validate);

    expect(error.data).toMatchObject({
      payload: { step: "secret" },
      type: "object_not_found",
    });
  });

  it("fails at `app` when Okta has no such app", async () => {
    stubOkta({
      "POST /oauth2/v1/token": token,
      [`GET ${APP_PATH}`]: () => answer(404, { errorCode: "E0000007" }),
    });

    const error = await connectorError(validate);

    expect(error.data).toMatchObject({
      payload: { code: "E0000007", status: 404, step: "app" },
      type: "object_not_found",
    });
  });

  it.each([
    ["isn't the AWS app", { name: "salesforce" }],
    ["doesn't use SAML", { signOnMode: "OPENID_CONNECT" }],
    ["is inactive", { status: "INACTIVE" }],
  ])("fails at `app` when the app %s", async (_, change) => {
    oktaWith({ app: { ...AWS_APP, ...change } });

    const error = await connectorError(validate);

    expect(error.data).toMatchObject({
      payload: { step: "app" },
      type: "validation_error",
    });
  });

  it("fails at `metadata` when the metadata has no entity ID", async () => {
    oktaWith({ metadata: "<md:EntityDescriptor/>" });

    const error = await connectorError(validate);

    expect(error.data).toMatchObject({
      payload: { step: "metadata" },
      type: "validation_error",
    });
  });
});

describe("install configuration", () => {
  const apply = () => caller().configuration.set(APP_INPUT);

  it("adds managedByP0 and sets joinAllRoles, keeping the rest of the app", async () => {
    const okta = oktaWith();

    await expect(apply()).resolves.toBeNull();

    const bodyOf = (call: string) =>
      JSON.parse(
        okta.fetch.mock.calls[okta.calls().indexOf(call)]?.[1]?.body as string
      );
    expect(bodyOf(`POST /api/v1/meta/schemas/apps/${APP_ID}/default`)).toEqual({
      definitions: {
        custom: {
          id: "#custom",
          properties: {
            managedByP0: {
              scope: "NONE",
              title: "Managed by P0",
              type: "boolean",
            },
          },
          type: "object",
        },
      },
    });
    expect(bodyOf(`PUT ${APP_PATH}`)).toEqual({
      ...AWS_APP,
      settings: { app: { ...AWS_APP.settings.app, joinAllRoles: true } },
    });
  });

  it("leaves the app alone when joinAllRoles is set", async () => {
    const okta = oktaWith({
      app: { ...AWS_APP, settings: { app: { joinAllRoles: true } } },
    });

    await apply();

    expect(okta.calls()).not.toContain(`PUT ${APP_PATH}`);
  });

  it("fails at `configure` when Okta refuses the schema change", async () => {
    stubOkta({
      "POST /oauth2/v1/token": token,
      [`GET ${APP_PATH}`]: () => answer(200, AWS_APP),
      [`POST /api/v1/meta/schemas/apps/${APP_ID}/default`]: () =>
        answer(403, { errorCode: "E0000006" }),
    });

    const error = await connectorError(apply);

    expect(error.data).toMatchObject({
      payload: { step: "configure" },
      type: "insufficient_privileges",
    });
  });
});
