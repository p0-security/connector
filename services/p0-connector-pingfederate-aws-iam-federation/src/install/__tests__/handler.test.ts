import { ConnectorError } from "@p0security/connector-core";
import { InsufficientAccessError, InvalidCredentialsError } from "ldapts";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  BIND_PASSWORD,
  connectorError,
  logger,
} from "../../__tests__/fixtures.ts";
import { type Directory, connectDirectory } from "../../ldap/client.ts";
import type * as metadataModule from "../../pingfederate/metadata.ts";
import {
  MetadataStatusError,
  getMetadata,
} from "../../pingfederate/metadata.ts";
import { connectorRouter } from "../../router.ts";
import { readBindPassword } from "../../secrets.ts";

vi.mock("../../secrets.ts");
vi.mock("../../ldap/client.ts");
vi.mock("../../pingfederate/metadata.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof metadataModule>()),
  getMetadata: vi.fn(),
}));

const ENTITY_ID = "https://sso.example.com";
const METADATA = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="${ENTITY_ID}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`;

const directory = {
  entryExists: vi.fn<Directory["entryExists"]>(),
  findAttributeType: vi.fn<Directory["findAttributeType"]>(),
  close: vi.fn<Directory["close"]>(),
};

const validate = () =>
  connectorRouter
    .createCaller({ logger })
    ["pingfederate-aws-iam-federation"].install.validation.get(APP_INPUT);

const failure = async () => (await connectorError(validate)).data;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readBindPassword).mockResolvedValue(BIND_PASSWORD);
  vi.mocked(connectDirectory).mockResolvedValue(directory);
  directory.entryExists.mockResolvedValue(true);
  directory.findAttributeType.mockResolvedValue({
    definition: "( 1.2.3 NAME 'awsRole' )",
    singleValued: false,
  });
  directory.close.mockResolvedValue();
  vi.mocked(getMetadata).mockResolvedValue(METADATA);
});

describe("install validation", () => {
  it("returns the entity ID, reading only", async () => {
    await expect(validate()).resolves.toEqual({ entityId: ENTITY_ID });

    expect(connectDirectory).toHaveBeenCalledWith(
      expect.objectContaining({ directoryUrl: APP_INPUT.directoryUrl }),
      BIND_PASSWORD
    );
    expect(directory.entryExists).toHaveBeenCalledWith(APP_INPUT.baseDn);
    expect(directory.findAttributeType).toHaveBeenCalledWith("awsRole");
    expect(directory.close).toHaveBeenCalled();
  });

  it.each([
    ["an ldap:// directory URL", { directoryUrl: "ldap://ldap.example.com" }],
    ["an http PingFederate URL", { pingFederateUrl: "http://sso.example.com" }],
    ["a CA certificate that isn't PEM", { caCertificate: "MIIB" }],
  ])("refuses %s", async (_, change) => {
    await expect(
      connectorRouter
        .createCaller({ logger })
        ["pingfederate-aws-iam-federation"].install.validation.get({
          ...APP_INPUT,
          ...change,
        })
    ).rejects.toThrow();
    expect(readBindPassword).not.toHaveBeenCalled();
  });

  it("fails at `secret` when the password can't be read", async () => {
    vi.mocked(readBindPassword).mockRejectedValue(
      new ConnectorError({
        message: "no secret",
        payload: { manager: "aws" },
        type: "object_not_found",
      })
    );

    expect(await failure()).toMatchObject({
      type: "object_not_found",
      payload: { manager: "aws", step: "secret" },
    });
  });

  it("fails at `bind` when the user store refuses the bind account", async () => {
    vi.mocked(connectDirectory).mockRejectedValue(
      new InvalidCredentialsError()
    );

    expect(await failure()).toMatchObject({
      type: "insufficient_privileges",
      payload: { ldapResult: 49, step: "bind" },
    });
  });

  it("fails at `bind` when the connector doesn't trust the certificate", async () => {
    vi.mocked(connectDirectory).mockRejectedValue(
      Object.assign(new Error("self-signed"), {
        code: "SELF_SIGNED_CERT_IN_CHAIN",
      })
    );

    const error = await failure();

    expect(error).toMatchObject({
      type: "validation_error",
      payload: { step: "bind" },
    });
    expect(error.message).toContain("CA's certificate");
  });

  it("fails at `bind` when the user store doesn't answer", async () => {
    vi.mocked(connectDirectory).mockRejectedValue(
      new Error("Connection timeout")
    );

    expect(await failure()).toMatchObject({
      type: "upstream_unavailable",
      payload: { step: "bind" },
    });
  });

  it("fails at `baseDn` when the base DN isn't an entry, and closes the connection", async () => {
    directory.entryExists.mockResolvedValue(false);

    expect(await failure()).toMatchObject({
      type: "validation_error",
      payload: { step: "baseDn" },
    });
    expect(directory.close).toHaveBeenCalled();
  });

  it("fails at `baseDn` when the bind account can't read it", async () => {
    directory.entryExists.mockRejectedValue(new InsufficientAccessError());

    expect(await failure()).toMatchObject({
      type: "insufficient_privileges",
      payload: { ldapResult: 50, step: "baseDn" },
    });
  });

  it.each([
    ["isn't in the schema", undefined],
    [
      "takes only one value",
      {
        definition: "( 1.2.3 NAME 'awsRole' SINGLE-VALUE )",
        singleValued: true,
      },
    ],
  ])("fails at `attribute` when the role attribute %s", async (_, found) => {
    directory.findAttributeType.mockResolvedValue(found);

    expect(await failure()).toMatchObject({
      type: "validation_error",
      payload: { step: "attribute" },
    });
    expect(getMetadata).not.toHaveBeenCalled();
  });

  it.each([
    [404, "validation_error"],
    [503, "upstream_unavailable"],
  ])(
    "fails at `metadata` when PingFederate answers %s",
    async (status, type) => {
      vi.mocked(getMetadata).mockRejectedValue(new MetadataStatusError(status));

      const error = await failure();

      expect(error).toMatchObject({ type, payload: { step: "metadata" } });
      expect(error.message).toContain("urn:amazon:webservices");
    }
  );

  it("fails at `metadata` when PingFederate can't be reached", async () => {
    vi.mocked(getMetadata).mockRejectedValue(
      Object.assign(new Error("getaddrinfo"), { code: "ENOTFOUND" })
    );

    const error = await failure();

    expect(error).toMatchObject({
      type: "upstream_unavailable",
      payload: { code: "ENOTFOUND", step: "metadata" },
    });
    expect(error.message).toContain("PingFederate");
  });

  it("fails at `metadata` when the metadata has no entity ID", async () => {
    vi.mocked(getMetadata).mockResolvedValue("<html></html>");

    expect(await failure()).toMatchObject({
      type: "validation_error",
      payload: { step: "metadata" },
    });
  });
});
