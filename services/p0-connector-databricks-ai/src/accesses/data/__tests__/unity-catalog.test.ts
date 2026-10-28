import { describe, expect, it, vi } from "vitest";

import {
  WORKSPACE_URL,
  accountContext,
  databricksCalls,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../../__tests__/http.ts";
import { newDatabricksClient } from "../../../databricks/client.ts";
import { newUnityCatalog } from "../unity-catalog.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const uc = () =>
  newUnityCatalog(
    newDatabricksClient(accountContext()).inWorkspace(WORKSPACE_URL)
  );

const sent = (fetchMock: ReturnType<typeof stubFetch>) =>
  databricksCalls(fetchMock).map(({ url, init }) => [
    init.method,
    url,
    init.body,
  ]);

// Each pins one unverified call (TODO(INT-810)), so the live check has one
// place to change.
describe("unverified calls", () => {
  it("moves an object's owner with a PATCH of its owner field", async () => {
    const fetchMock = stubFetch(() => jsonResponse({}));

    await uc().setOwner("tables", "main.sales.summary", "data-admins");

    expect(sent(fetchMock)).toEqual([
      [
        "PATCH",
        `${WORKSPACE_URL}/api/2.1/unity-catalog/tables/main.sales.summary`,
        JSON.stringify({ owner: "data-admins" }),
      ],
    ]);
  });
});

describe("403", () => {
  it("says P0 must be a metastore admin", async () => {
    stubFetch(() =>
      jsonResponse(
        { error_code: "PERMISSION_DENIED", message: "no" },
        { status: 403 }
      )
    );

    await expect(
      uc().directPrivileges(
        { type: "schema", fullName: "main.sales" },
        "agent-app-id"
      )
    ).rejects.toMatchObject({
      message:
        "P0's service principal can't manage privileges on schema main.sales. Check that it is a metastore admin, for example by re-applying the account's Terraform.",
      data: { type: "insufficient_privileges" },
    });
  });
});
