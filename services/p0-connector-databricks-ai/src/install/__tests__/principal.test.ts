import { createLogger } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeAccount,
  OWN_PRINCIPAL,
  databricks,
  fakeAccount,
} from "../../__tests__/databricks.ts";
import {
  ACCOUNT_API,
  accountContext,
  databricksCalls,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { connectorRouter } from "../../router.ts";
import type { StageInput } from "../definition.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const NAME = "p0-agent-req_123";

let account: FakeAccount;

beforeEach(() => {
  account = fakeAccount();
});

// Calling through the connector router also proves the route is registered
// at `databricks-ai.install.principal.stage`.
const stage = (input: Partial<StageInput> = {}) =>
  connectorRouter
    .createCaller({ logger: createLogger() })
    ["databricks-ai"].install.principal.stage({
      ...accountContext(),
      principalName: NAME,
      ...input,
    });

describe("install principal stage", () => {
  it("creates the bare principal when none has the name, and returns its application ID", async () => {
    const fetchMock = stubFetch(databricks(account));

    const { applicationId } = await stage();

    const created = account.servicePrincipals.find(
      (p) => p.displayName === NAME
    );
    expect(applicationId).toBe(created?.applicationId);
    expect(created?.active).toBe(true);
    const writes = databricksCalls(fetchMock).filter(
      ({ init }) => init.method !== "GET"
    );
    expect(
      writes.map(({ url, init }) => [init.method, url, init.body])
    ).toEqual([
      [
        "POST",
        `${ACCOUNT_API}/scim/v2/ServicePrincipals`,
        JSON.stringify({ displayName: NAME, active: true }),
      ],
    ]);
  });

  it("returns the principal an earlier stage created, creating nothing", async () => {
    stubFetch(databricks(account));
    const first = await stage();
    const fetchMock = stubFetch(databricks(account));

    await expect(stage()).resolves.toEqual(first);
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
  });

  it("refuses two principals with the name", async () => {
    for (const id of ["8100000000000001", "8100000000000002"]) {
      account.servicePrincipals.push({
        id,
        applicationId: `00000000-0000-4000-8000-${id.slice(-12)}`,
        displayName: NAME,
      });
    }
    const fetchMock = stubFetch(databricks(account));

    await expect(stage()).rejects.toMatchObject({
      message: expect.stringContaining("8100000000000001, 8100000000000002"),
      data: { type: "validation_error" },
    });
    expect(
      databricksCalls(fetchMock).every(({ init }) => init.method === "GET")
    ).toBe(true);
  });

  it("refuses P0's own principal", async () => {
    account.servicePrincipals = [{ ...OWN_PRINCIPAL, displayName: NAME }];
    stubFetch(databricks(account));

    await expect(stage()).rejects.toMatchObject({
      message:
        "P0 cannot grant access to its own Databricks service principal.",
    });
  });

  it("says P0 isn't an account admin when account SCIM refuses it", async () => {
    account.refuse["POST /scim/v2/ServicePrincipals"] = 403;
    stubFetch(databricks(account));

    await expect(stage()).rejects.toMatchObject({
      data: { type: "insufficient_privileges" },
    });
  });

  it.each([
    ["a name outside the namespace", { principalName: "alice" }],
    ["a name with a space", { principalName: "p0-agent-a b" }],
    [
      "an unknown field, which the strict schema refuses",
      { principalNames: NAME },
    ],
  ])("refuses %s before calling anything", async (_, input) => {
    const fetchMock = stubFetch(databricks(account));

    await expect(stage(input as Partial<StageInput>)).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
