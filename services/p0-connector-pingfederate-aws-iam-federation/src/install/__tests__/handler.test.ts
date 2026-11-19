import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  SCIM_PASSWORD,
  connectorError,
  logger,
} from "../../__tests__/fixtures.ts";
import type * as metadataModule from "../../pingfederate/metadata.ts";
import {
  MetadataStatusError,
  getMetadata,
} from "../../pingfederate/metadata.ts";
import type * as scimModule from "../../pingfederate/scim.ts";
import { ScimStatusError, scimClient } from "../../pingfederate/scim.ts";
import { connectorRouter } from "../../router.ts";
import { readScimPassword } from "../../secrets.ts";

vi.mock("../../secrets.ts");
vi.mock("../../pingfederate/metadata.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof metadataModule>()),
  getMetadata: vi.fn(),
}));
vi.mock("../../pingfederate/scim.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof scimModule>()),
  scimClient: vi.fn(),
}));

const scim = {
  findUsers: vi.fn<scimModule.Scim["findUsers"]>(),
  getExtensionAttributes: vi.fn<scimModule.Scim["getExtensionAttributes"]>(),
};

const AWS_ROLE = {
  name: "awsRole",
  multiValued: true,
  mutability: "readWrite",
};

const ENTITY_ID = "https://sso.example.com";
const METADATA = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor entityID="${ENTITY_ID}" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>`;

const validate = () =>
  connectorRouter
    .createCaller({ logger })
    ["pingfederate-aws-iam-federation"].install.validation.get(APP_INPUT);

const failure = async () => (await connectorError(validate)).data;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readScimPassword).mockResolvedValue(SCIM_PASSWORD);
  vi.mocked(scimClient).mockReturnValue(scim);
  scim.findUsers.mockResolvedValue([]);
  scim.getExtensionAttributes.mockResolvedValue([AWS_ROLE]);
  vi.mocked(getMetadata).mockResolvedValue(METADATA);
});

describe("install validation", () => {
  it("returns the entity ID, reading only", async () => {
    await expect(validate()).resolves.toEqual({ entityId: ENTITY_ID });

    expect(scimClient).toHaveBeenCalledWith(
      expect.objectContaining({ scimUsername: APP_INPUT.scimUsername }),
      SCIM_PASSWORD
    );
    expect(scim.findUsers).toHaveBeenCalled();
    expect(scim.getExtensionAttributes).toHaveBeenCalled();
  });

  it.each([
    ["an http PingFederate URL", { pingFederateUrl: "http://sso.example.com" }],
    ["a role attribute with a dot", { roleAttribute: "aws.role" }],
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
    expect(readScimPassword).not.toHaveBeenCalled();
  });

  it("fails at `secret` when the password can't be read", async () => {
    vi.mocked(readScimPassword).mockRejectedValue(
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

  it("fails at `scim` when PingFederate refuses the credentials", async () => {
    scim.findUsers.mockRejectedValue(
      new ScimStatusError(401, "Basic auth failed")
    );

    expect(await failure()).toMatchObject({
      type: "insufficient_privileges",
      payload: { status: 401, step: "scim" },
    });
  });

  it("fails at `scim` and names the mapping when the email filter is undefined", async () => {
    scim.findUsers.mockRejectedValue(
      new ScimStatusError(
        400,
        "Invalid filter value. 'emails.work.value' is not a defined attribute"
      )
    );

    const error = await failure();

    expect(error).toMatchObject({
      type: "validation_error",
      payload: { step: "scim" },
    });
    expect(error.message).toContain("Read Users mapping");
  });

  it("fails at `scim` when the connector doesn't trust the certificate", async () => {
    scim.findUsers.mockRejectedValue(
      Object.assign(new Error("self-signed"), {
        code: "SELF_SIGNED_CERT_IN_CHAIN",
      })
    );

    const error = await failure();

    expect(error).toMatchObject({
      type: "validation_error",
      payload: { step: "scim" },
    });
    expect(error.message).toContain("CA's certificate");
  });

  it("fails at `scim` when PingFederate doesn't answer", async () => {
    scim.findUsers.mockRejectedValue(
      Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })
    );

    expect(await failure()).toMatchObject({
      type: "upstream_unavailable",
      payload: { code: "ETIMEDOUT", step: "scim" },
    });
  });

  it.each([
    ["PingFederate has no custom schema", undefined],
    ["the schema has no role attribute", [{ ...AWS_ROLE, name: "other" }]],
    [
      "the role attribute takes one value",
      [{ ...AWS_ROLE, multiValued: false }],
    ],
    [
      "the role attribute is read-only",
      [{ ...AWS_ROLE, mutability: "readOnly" }],
    ],
  ])("fails at `attribute` when %s", async (_, attributes) => {
    scim.getExtensionAttributes.mockResolvedValue(attributes);

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
