import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  connectorError,
  logger,
} from "../../../__tests__/fixtures.ts";
import { connectorRouter } from "../../../router.ts";
import { addRole, findUserId, removeRole } from "../assignment.ts";

vi.mock("../assignment.ts");

const EMAIL = "ada@example.com";
const USER_ID = "00u1ada";
const ROLE = "p0-pool-1";
const CONTEXT = { requestId: "request-1", ...APP_INPUT };

const role = () =>
  connectorRouter.createCaller({ logger })["okta-aws-iam-federation"].accesses
    .role;

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("role access", () => {
  it("provisions an existing user to their Okta ID", async () => {
    vi.mocked(findUserId).mockResolvedValue(USER_ID);

    await expect(
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    ).resolves.toBe(USER_ID);
  });

  it("refuses to provision a user Okta doesn't have", async () => {
    vi.mocked(findUserId).mockResolvedValue(null);

    const error = await connectorError(() =>
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    );

    expect(error.data.type).toBe("object_not_found");
  });

  it("uses the label as the resource, with no Okta call", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      role().createAccessResource({ context: CONTEXT, resourceBody: ROLE })
    ).resolves.toBe(ROLE);
    await role().addPoliciesToResource({
      context: CONTEXT,
      policies: [null],
      resourceId: ROLE,
    });
    await role().deleteAccessResource({ context: CONTEXT, resourceId: ROLE });

    expect(fetch).not.toHaveBeenCalled();
  });

  it("binds by adding the label", async () => {
    await role().bindAccessResource({
      context: CONTEXT,
      resourceId: ROLE,
      userBody: EMAIL,
      userId: USER_ID,
    });

    expect(addRole).toHaveBeenCalledWith(
      expect.objectContaining({ ...APP_INPUT, email: EMAIL, role: ROLE }),
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
      expect.objectContaining({ ...APP_INPUT, email: EMAIL, role: ROLE }),
      expect.anything()
    );
  });
});
