import { beforeEach, describe, expect, it, vi } from "vitest";

import { APP_INPUT } from "../../__tests__/fixtures.ts";
import { callPingFederate } from "../http.ts";
import { SCIM_EXTENSION, ScimStatusError, scimClient } from "../scim.ts";

vi.mock("../http.ts");

const scim = () => scimClient(APP_INPUT, "pa55word");

const replying = (status: number, body: unknown) =>
  vi
    .mocked(callPingFederate)
    .mockResolvedValue({ status, body: JSON.stringify(body) });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("findUsers", () => {
  it("searches by work email with Basic credentials, and returns the IDs", async () => {
    replying(200, {
      Resources: [{ id: "9b87b8dc-67ce-4729-9ecd-d324a1905819" }, {}],
    });

    await expect(scim().findUsers('ada"@example.com')).resolves.toEqual([
      "9b87b8dc-67ce-4729-9ecd-d324a1905819",
      null,
    ]);

    expect(callPingFederate).toHaveBeenCalledWith(APP_INPUT, {
      method: "GET",
      path: `/pf-scim/v2/Users?filter=${encodeURIComponent('emails.work.value eq "ada\\"@example.com"')}&attributes=id`,
      headers: {
        accept: "application/scim+json",
        authorization: `Basic ${Buffer.from("p0:pa55word").toString("base64")}`,
      },
    });
  });

  it("throws the status and PingFederate's detail", async () => {
    replying(401, { status: "401", detail: "Basic auth failed for p0" });

    const error = await scim()
      .findUsers("ada@example.com")
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ScimStatusError);
    expect(error).toMatchObject({
      status: 401,
      detail: "Basic auth failed for p0",
    });
  });

  it("throws a status with a body that isn't JSON", async () => {
    vi.mocked(callPingFederate).mockResolvedValue({
      status: 502,
      body: "<html>Bad gateway</html>",
    });

    await expect(scim().findUsers("ada@example.com")).rejects.toMatchObject({
      status: 502,
      detail: undefined,
    });
  });
});

describe("getExtensionAttributes", () => {
  it("reads the custom schema's attributes", async () => {
    const awsRole = {
      name: "awsRole",
      multiValued: true,
      mutability: "readWrite",
    };
    replying(200, { id: SCIM_EXTENSION, attributes: [awsRole] });

    await expect(scim().getExtensionAttributes()).resolves.toEqual([awsRole]);
    expect(callPingFederate).toHaveBeenCalledWith(
      APP_INPUT,
      expect.objectContaining({
        path: `/pf-scim/v2/Schemas/${SCIM_EXTENSION}`,
      })
    );
  });

  it("returns undefined when PingFederate has no custom schema", async () => {
    replying(404, { status: "404", detail: "Schema not found." });

    await expect(scim().getExtensionAttributes()).resolves.toBeUndefined();
  });
});

describe("addValue and removeValue", () => {
  const ID = "9b87b8dc-67ce-4729-9ecd-d324a1905819";
  const ROLE = "arn:aws:iam::1:role/r,arn:aws:iam::1:saml-provider/p";

  beforeEach(() => {
    replying(200, { id: ID });
  });

  const sentBody = () =>
    JSON.parse(vi.mocked(callPingFederate).mock.calls[0]?.[1].body ?? "");

  it("adds one value with a PATCH", async () => {
    await scim().addValue(ID, "awsRole", ROLE);

    expect(callPingFederate).toHaveBeenCalledWith(
      APP_INPUT,
      expect.objectContaining({
        method: "PATCH",
        path: `/pf-scim/v2/Users/${ID}`,
        headers: expect.objectContaining({
          "content-type": "application/scim+json",
        }),
      })
    );
    expect(sentBody()).toEqual({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [
        { op: "add", path: `${SCIM_EXTENSION}:awsRole`, value: [ROLE] },
      ],
    });
  });

  it("removes one value by a value filter", async () => {
    await scim().removeValue(ID, "awsRole", ROLE);

    expect(sentBody().Operations).toEqual([
      { op: "remove", path: `${SCIM_EXTENSION}:awsRole[value eq "${ROLE}"]` },
    ]);
  });

  it("throws a 404 for a user PingFederate doesn't have", async () => {
    replying(404, { status: "404", detail: `ID ${ID} was not found.` });

    await expect(scim().addValue(ID, "awsRole", ROLE)).rejects.toMatchObject({
      status: 404,
    });
  });
});
