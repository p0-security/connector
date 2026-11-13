import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_ID,
  APP_INPUT,
  CLIENT_ID,
  CLIENT_SECRET,
  ENVIRONMENT_ID,
  answer,
  connectorError,
  logger,
  stubPingOne,
} from "../../__tests__/fixtures.ts";
import { connectorRouter } from "../../router.ts";
import { readClientSecret } from "../../secrets.ts";

vi.mock("../../secrets.ts");

const TOKEN = `POST auth.pingone.com/${ENVIRONMENT_ID}/as/token`;
const API = `api.pingone.com/v1/environments/${ENVIRONMENT_ID}`;
const GET_APP = `GET ${API}/applications/${APP_ID}`;
const GET_MAPPINGS = `${GET_APP}/attributes`;
const GET_SCHEMAS = `GET ${API}/schemas`;
const GET_USER_ATTRIBUTES = `${GET_SCHEMAS}/user-schema/attributes`;
const GET_METADATA = `GET auth.pingone.com/${ENVIRONMENT_ID}/saml20/metadata/${APP_ID}`;

const ENTITY_ID = `https://auth.pingone.com/${ENVIRONMENT_ID}`;
const METADATA = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="${ENTITY_ID}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`;

const SAML_APP = {
  id: APP_ID,
  name: "AWS Production",
  enabled: true,
  protocol: "SAML",
  type: "WEB_APP",
  nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
};

const URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
const ROLE_MAPPING = {
  name: "https://aws.amazon.com/SAML/Attributes/Role",
  value: "${user.awsRoles}",
  nameFormat: URI,
};
const SOURCE_IDENTITY_MAPPING = {
  name: "https://aws.amazon.com/SAML/Attributes/SourceIdentity",
  value: "${user.email}",
  nameFormat: URI,
};
const MAPPINGS = [
  { name: "saml_subject", value: "${user.id}" },
  ROLE_MAPPING,
  SOURCE_IDENTITY_MAPPING,
];

// PingOne sends `null` for an attribute without allowed values.
const ROLE_ATTRIBUTE = {
  name: "awsRoles",
  type: "STRING",
  multiValued: true,
  enumeratedValues: null,
  regexValidation: null,
};
const USER_ATTRIBUTES = [
  { name: "email", type: "STRING", multiValued: false },
  ROLE_ATTRIBUTE,
];

const token = () => answer(200, { access_token: "at", token_type: "Bearer" });

const pingOneWith = ({
  app = SAML_APP,
  mappings = MAPPINGS,
  attributes = USER_ATTRIBUTES,
  metadata = METADATA,
}: {
  app?: object;
  mappings?: object[];
  attributes?: object[];
  metadata?: string;
} = {}) =>
  stubPingOne({
    [TOKEN]: token,
    [GET_APP]: () => answer(200, app),
    [GET_MAPPINGS]: () => answer(200, { _embedded: { attributes: mappings } }),
    [GET_SCHEMAS]: () =>
      answer(200, {
        _embedded: { schemas: [{ id: "user-schema", name: "User" }] },
      }),
    [GET_USER_ATTRIBUTES]: () => answer(200, { _embedded: { attributes } }),
    [GET_METADATA]: () => new Response(metadata),
  });

const validate = () =>
  connectorRouter
    .createCaller({ logger })
    ["pingone-aws-iam-federation"].install.validation.get(APP_INPUT);

const failure = async () => (await connectorError(validate)).data;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readClientSecret).mockResolvedValue(CLIENT_SECRET);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("install validation", () => {
  it("returns the app's name and entity ID, reading only", async () => {
    const pingOne = pingOneWith();

    await expect(validate()).resolves.toEqual({
      entityId: ENTITY_ID,
      name: "AWS Production",
    });
    expect(pingOne.calls()).toEqual([
      TOKEN,
      GET_APP,
      GET_MAPPINGS,
      GET_SCHEMAS,
      GET_USER_ATTRIBUTES,
      GET_METADATA,
    ]);
  });

  it("asks for a token with the client ID and secret", async () => {
    const pingOne = pingOneWith();

    await validate();

    const init = pingOne.fetch.mock.calls[0]?.[1];
    expect(new URLSearchParams(init?.body as string).get("grant_type")).toBe(
      "client_credentials"
    );
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`
    );
  });

  it.each([
    ["invalid_client", "insufficient_privileges"],
    ["unauthorized_client", "validation_error"],
  ])("fails at `token` when PingOne answers %s", async (code, type) => {
    stubPingOne({ [TOKEN]: () => answer(401, { error: code }) });

    expect(await failure()).toMatchObject({
      payload: { code, step: "token" },
      type,
    });
  });

  it("fails at `secret` when the client secret can't be read", async () => {
    vi.mocked(readClientSecret).mockRejectedValue(
      new ConnectorError({
        message: "missing",
        payload: { manager: "aws" },
        type: "object_not_found",
      })
    );

    expect(await failure()).toMatchObject({
      payload: { step: "secret" },
      type: "object_not_found",
    });
  });

  it("fails at `app` when PingOne has no such app", async () => {
    stubPingOne({
      [TOKEN]: token,
      [GET_APP]: () => answer(404, { code: "NOT_FOUND" }),
    });

    expect(await failure()).toMatchObject({
      payload: { code: "NOT_FOUND", status: 404, step: "app" },
      type: "object_not_found",
    });
  });

  it.each([
    ["isn't a SAML app", { protocol: "OPENID_CONNECT" }],
    ["is disabled", { enabled: false }],
    ["has no NameID format", { nameIdFormat: undefined }],
    [
      "has an unspecified NameID format",
      { nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" },
    ],
  ])("fails at `app` when the app %s", async (_, change) => {
    pingOneWith({ app: { ...SAML_APP, ...change } });

    expect(await failure()).toMatchObject({
      payload: { step: "app" },
      type: "validation_error",
    });
  });

  it.each([
    ["has no Role mapping", [SOURCE_IDENTITY_MAPPING]],
    [
      "maps Role from another attribute",
      [{ ...ROLE_MAPPING, value: "${user.groups}" }, SOURCE_IDENTITY_MAPPING],
    ],
    ["has no SourceIdentity mapping", [ROLE_MAPPING]],
    [
      "maps SourceIdentity from the username",
      [ROLE_MAPPING, { ...SOURCE_IDENTITY_MAPPING, value: "${user.username}" }],
    ],
    [
      "sends SourceIdentity with the basic name format",
      [
        ROLE_MAPPING,
        {
          ...SOURCE_IDENTITY_MAPPING,
          nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        },
      ],
    ],
  ])("fails at `mappings` when the app %s", async (_, mappings) => {
    pingOneWith({ mappings });

    expect(await failure()).toMatchObject({
      payload: { step: "mappings" },
      type: "validation_error",
    });
  });

  it.each([
    ["doesn't exist", []],
    ["is single-valued", [{ ...ROLE_ATTRIBUTE, multiValued: false }]],
    ["isn't text", [{ ...ROLE_ATTRIBUTE, type: "JSON" }]],
    [
      "has a list of allowed values",
      [{ ...ROLE_ATTRIBUTE, enumeratedValues: [{ value: "x" }] }],
    ],
    [
      "has a pattern of allowed values",
      [{ ...ROLE_ATTRIBUTE, regexValidation: { pattern: "^arn:.*$" } }],
    ],
  ])(
    "fails at `attribute` when the role attribute %s",
    async (_, attributes) => {
      pingOneWith({ attributes });

      expect(await failure()).toMatchObject({
        payload: { step: "attribute" },
        type: "validation_error",
      });
    }
  );

  it("accepts an empty list of allowed values", async () => {
    pingOneWith({ attributes: [{ ...ROLE_ATTRIBUTE, enumeratedValues: [] }] });

    await expect(validate()).resolves.toMatchObject({ entityId: ENTITY_ID });
  });

  it("fails at `metadata` when the metadata has no entity ID", async () => {
    pingOneWith({ metadata: "<md:EntityDescriptor/>" });

    expect(await failure()).toMatchObject({
      payload: { step: "metadata" },
      type: "validation_error",
    });
  });
});
