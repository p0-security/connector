import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  connectorError,
  logger,
} from "../../../__tests__/fixtures.ts";
import { connectorRouter } from "../../../router.ts";
import { addRole, findUserId, removeRole } from "../assignment.ts";

vi.mock("../assignment.ts");

const EMAIL = "ada@example.com";
const USER_ID = "9b87b8dc-67ce-4729-9ecd-d324a1905819";
const ROLE =
  "arn:aws:iam::123456789012:role/p0-pool-1,arn:aws:iam::123456789012:saml-provider/pingfederate";
const CONTEXT = { requestId: "request-1", ...APP_INPUT };

const role = () =>
  connectorRouter.createCaller({ logger })["pingfederate-aws-iam-federation"]
    .accesses.role;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("role access", () => {
  it("provisions an existing user to their SCIM ID", async () => {
    vi.mocked(findUserId).mockResolvedValue(USER_ID);

    await expect(
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    ).resolves.toBe(USER_ID);
  });

  it("refuses to provision a user PingFederate doesn't have", async () => {
    vi.mocked(findUserId).mockResolvedValue(null);

    const error = await connectorError(() =>
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    );

    expect(error.data.type).toBe("object_not_found");
  });

  it("uses the label as the resource, with no PingFederate call", async () => {
    await expect(
      role().createAccessResource({ context: CONTEXT, resourceBody: ROLE })
    ).resolves.toBe(ROLE);
    await role().addPoliciesToResource({
      context: CONTEXT,
      policies: [null],
      resourceId: ROLE,
    });
    await role().deleteAccessResource({ context: CONTEXT, resourceId: ROLE });

    expect(addRole).not.toHaveBeenCalled();
    expect(removeRole).not.toHaveBeenCalled();
  });

  it("binds by adding the label", async () => {
    await role().bindAccessResource({
      context: CONTEXT,
      resourceId: ROLE,
      userBody: EMAIL,
      userId: USER_ID,
    });

    expect(addRole).toHaveBeenCalledWith(
      expect.objectContaining({ ...APP_INPUT, userId: USER_ID, role: ROLE }),
      expect.anything()
    );
  });

  it("unbinds by removing the label", async () => {
    await role().unbindAccessResource({
      context: CONTEXT,
      resourceId: ROLE,
      userBody: EMAIL,
      userId: USER_ID,
    });

    expect(removeRole).toHaveBeenCalledWith(
      expect.objectContaining({ ...APP_INPUT, userId: USER_ID, role: ROLE }),
      expect.anything()
    );
  });
});
