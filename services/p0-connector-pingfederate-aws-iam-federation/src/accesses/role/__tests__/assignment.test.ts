import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  SCIM_PASSWORD,
  connectorError,
  logger,
  scim,
} from "../../../__tests__/fixtures.ts";
import type * as scimModule from "../../../pingfederate/scim.ts";
import { ScimStatusError, scimClient } from "../../../pingfederate/scim.ts";
import { readScimPassword } from "../../../secrets.ts";
import { addRole, findUserId, removeRole } from "../assignment.ts";

vi.mock("../../../secrets.ts");
vi.mock("../../../pingfederate/scim.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof scimModule>()),
  scimClient: vi.fn(),
}));

const EMAIL = "ada@example.com";
const USER_ID = "9b87b8dc-67ce-4729-9ecd-d324a1905819";
const ROLE =
  "arn:aws:iam::123456789012:role/p0-pool-1,arn:aws:iam::123456789012:saml-provider/pingfederate";
const ASSIGNMENT = { ...APP_INPUT, userId: USER_ID, role: ROLE };

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readScimPassword).mockResolvedValue(SCIM_PASSWORD);
  vi.mocked(scimClient).mockReturnValue(scim);
  scim.findUsers.mockResolvedValue([USER_ID]);
  scim.addValue.mockResolvedValue();
  scim.removeValue.mockResolvedValue();
});

describe("findUserId", () => {
  it("finds the user by work email", async () => {
    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBe(USER_ID);

    expect(scimClient).toHaveBeenCalledWith(APP_INPUT, SCIM_PASSWORD);
    expect(scim.findUsers).toHaveBeenCalledWith(EMAIL);
  });

  it("returns null when no user has the email", async () => {
    scim.findUsers.mockResolvedValue([]);

    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBeNull();
  });

  it("refuses an email that more than one user has", async () => {
    scim.findUsers.mockResolvedValue([USER_ID, `${USER_ID}2`]);

    const error = await connectorError(() =>
      findUserId(APP_INPUT, EMAIL, logger)
    );

    expect(error.data).toMatchObject({
      type: "validation_error",
      payload: { count: 2 },
    });
  });

  it("names the read mapping when PingFederate gives no ID", async () => {
    scim.findUsers.mockResolvedValue([null]);

    const error = await connectorError(() =>
      findUserId(APP_INPUT, EMAIL, logger)
    );

    expect(error.data.type).toBe("validation_error");
    expect(error.message).toContain("Read Users mapping");
  });

  it("maps refused credentials", async () => {
    scim.findUsers.mockRejectedValue(new ScimStatusError(401, undefined));

    const error = await connectorError(() =>
      findUserId(APP_INPUT, EMAIL, logger)
    );

    expect(error.data.type).toBe("insufficient_privileges");
  });
});

describe.each([
  ["addRole", addRole, scim.addValue],
  ["removeRole", removeRole, scim.removeValue],
])("%s", (_, change, call) => {
  it("changes one value of the role attribute", async () => {
    await expect(change(ASSIGNMENT, logger)).resolves.toBeNull();

    expect(call).toHaveBeenCalledWith(USER_ID, APP_INPUT.roleAttribute, ROLE);
  });

  it("passes on PingFederate's detail when it fails the change", async () => {
    call.mockRejectedValue(
      new ScimStatusError(500, "There was an error processing the request.")
    );

    const error = await connectorError(() => change(ASSIGNMENT, logger));

    expect(error.data).toMatchObject({
      type: "upstream_unavailable",
      payload: { status: 500 },
    });
    expect(error.message).toContain("There was an error processing");
  });
});

it("addRole fails for a user PingFederate doesn't have", async () => {
  scim.addValue.mockRejectedValue(new ScimStatusError(404, "not found"));

  const error = await connectorError(() => addRole(ASSIGNMENT, logger));

  expect(error.data.type).toBe("object_not_found");
});

it("removeRole does nothing for a user PingFederate doesn't have", async () => {
  scim.removeValue.mockRejectedValue(new ScimStatusError(404, "not found"));

  await expect(removeRole(ASSIGNMENT, logger)).resolves.toBeNull();
});
