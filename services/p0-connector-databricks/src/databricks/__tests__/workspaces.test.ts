import { describe, expect, it, vi } from "vitest";

import {
  METASTORE_ASSIGNMENT,
  METASTORE_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  bindingResponse,
  fetchCalls,
  isBinding,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { newDatabricksClient } from "../client.ts";
import {
  WORKSPACE_PAIR_ERROR,
  bindWorkspace,
  hasWorkspacePair,
  inBoundWorkspace,
  workspaceContext,
} from "../workspaces.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);
vi.mock("@p0security/connector-core", async (importOriginal) =>
  (await import("../../__tests__/logs.ts")).recordingLoggerModule(
    importOriginal
  )
);

resetBetweenTests();

const OTHER_ACCOUNT_ID = "5b0c3a2e-9d1f-4e8a-b7c6-2f4e6a8c0d1e";

const workspaceRef = { workspaceId: WORKSPACE_ID, workspaceUrl: WORKSPACE_URL };

const databricksCalls = (mock: ReturnType<typeof stubFetch>) =>
  fetchCalls(mock).filter((call) => !isTokenExchange(call));

describe("workspaceContext", () => {
  it("takes a workspace ID and the URL that serves it", () => {
    expect(
      workspaceContext.parse({ ...accountContext(), ...workspaceRef })
    ).toEqual({ ...accountContext(), ...workspaceRef });
  });

  it.each(["", "12a4", "../123", "123/permissions", " 123"])(
    "rejects the workspace ID %j",
    (workspaceId) => {
      expect(() =>
        workspaceContext.parse({
          ...accountContext(),
          workspaceId,
          workspaceUrl: WORKSPACE_URL,
        })
      ).toThrow();
    }
  );

  it.each([
    "https://evil.example",
    "https://dbc-1234abcd-5678.cloud.databricks.com.evil.example",
    "http://dbc-1234abcd-5678.cloud.databricks.com",
    `${WORKSPACE_URL}/api`,
  ])("rejects the workspace URL %j", (workspaceUrl) => {
    expect(() =>
      workspaceContext.parse({
        ...accountContext(),
        workspaceId: WORKSPACE_ID,
        workspaceUrl,
      })
    ).toThrow();
  });

  it("requires the workspace URL", () => {
    expect(() =>
      workspaceContext.parse({ ...accountContext(), workspaceId: WORKSPACE_ID })
    ).toThrow();
  });
});

describe("hasWorkspacePair", () => {
  it.each([
    [{}, true],
    [workspaceRef, true],
    [{ workspaceId: WORKSPACE_ID }, false],
    [{ workspaceUrl: WORKSPACE_URL }, false],
  ])("is %j → %s", (value, expected) => {
    expect(hasWorkspacePair(value)).toBe(expected);
  });

  it("has a message naming both fields", () => {
    expect(WORKSPACE_PAIR_ERROR).toBe(
      "workspaceId and workspaceUrl must be sent together"
    );
  });
});

describe("bindWorkspace", () => {
  const bind = (
    ref: { workspaceId: string; workspaceUrl: string } = workspaceRef,
    context = accountContext()
  ) => bindWorkspace(newDatabricksClient(context), ref);

  const mismatch = (requested: string, actual: string) => ({
    message: `Databricks workspace URL ${WORKSPACE_URL} belongs to workspace ${actual}, not ${requested}. Check the URL saved for workspace ${requested} in P0.`,
    data: { type: "validation_error" },
  });

  const noMetastore = {
    message: `Databricks workspace ${WORKSPACE_ID} has no Unity Catalog metastore. P0 needs one to confirm the workspace's URL. Assign the workspace a metastore, then try again.`,
    data: { type: "validation_error" },
  };

  it("returns the workspace and its metastore when the URL answers for the ID", async () => {
    const fetchMock = stubFetch(() => bindingResponse());

    await expect(bind()).resolves.toEqual({
      workspaceId: WORKSPACE_ID,
      metastoreId: METASTORE_ID,
    });

    const [call] = databricksCalls(fetchMock);
    expect(call?.url).toBe(`${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`);
    expect(call?.init.method).toBe("GET");
    expect(call?.init.headers.Authorization).toBe("Bearer dbx-token-1");
  });

  it("refuses a URL that answers for another workspace", async () => {
    stubFetch(() => bindingResponse("42"));

    await expect(bind()).rejects.toMatchObject(mismatch(WORKSPACE_ID, "42"));
  });

  it("matches an ID with leading zeros, which names the same workspace", async () => {
    stubFetch(() => bindingResponse());

    await expect(
      bind({ ...workspaceRef, workspaceId: `00${WORKSPACE_ID}` })
    ).resolves.toMatchObject({ metastoreId: METASTORE_ID });
  });

  // The cache holds what the URL answered, never a verdict, so every call
  // compares again.
  it("still refuses a different requested ID once the URL's binding is cached", async () => {
    const fetchMock = stubFetch(() => bindingResponse());

    await bind();
    await expect(
      bind({ ...workspaceRef, workspaceId: "42" })
    ).rejects.toMatchObject(mismatch("42", WORKSPACE_ID));
    expect(databricksCalls(fetchMock)).toHaveLength(1);
  });

  it("reads each URL once per principal", async () => {
    const fetchMock = stubFetch(() => bindingResponse());

    await bind();
    await bind();
    await bind(workspaceRef, accountContext({ accountId: OTHER_ACCOUNT_ID }));

    expect(databricksCalls(fetchMock)).toHaveLength(2);
  });

  it("doesn't cache a failed binding, so the next call asks again", async () => {
    let answer = jsonResponse(
      { error_code: "TEMPORARILY_UNAVAILABLE", message: "try again" },
      { status: 503 }
    );
    const fetchMock = stubFetch(() => answer);

    await expect(bind()).rejects.toMatchObject({
      data: { type: "upstream_unavailable" },
    });
    answer = bindingResponse();

    await expect(bind()).resolves.toMatchObject({ metastoreId: METASTORE_ID });
    expect(databricksCalls(fetchMock)).toHaveLength(2);
  });

  it("says the workspace has no metastore on a 404 carrying METASTORE_DOES_NOT_EXIST", async () => {
    stubFetch(() =>
      jsonResponse(
        { error_code: "METASTORE_DOES_NOT_EXIST", message: "no metastore" },
        { status: 404 }
      )
    );

    await expect(bind()).rejects.toMatchObject(noMetastore);
  });

  it.each([
    ["no error code", { message: "not found" }],
    ["the generic NOT_FOUND", { error_code: "NOT_FOUND" }],
  ])("fails as itself on a 404 with %s", async (_, body) => {
    stubFetch(() => jsonResponse(body, { status: 404 }));

    await expect(bind()).rejects.toMatchObject({
      message: expect.stringMatching(
        /^Databricks GET \/api\/2\.1\/unity-catalog\/current-metastore-assignment failed \(404\)/
      ),
      data: { type: "object_not_found", payload: { status: 404 } },
    });
  });

  it("fails as itself when Databricks refuses the principal", async () => {
    stubFetch(() =>
      jsonResponse(
        { error_code: "PERMISSION_DENIED", message: "no" },
        { status: 403 }
      )
    );

    await expect(bind()).rejects.toMatchObject({
      data: { type: "insufficient_privileges", payload: { status: 403 } },
    });
  });

  it("refuses a workspace ID that JSON parsing rounded", async () => {
    stubFetch(() =>
      jsonResponse({ workspace_id: 2 ** 53 + 2, metastore_id: METASTORE_ID })
    );

    await expect(bind()).rejects.toMatchObject({
      message:
        "Databricks Unity Catalog current metastore assignment returned an unexpected response",
      data: { type: "unknown" },
    });
  });

  it("refuses a response without a metastore ID", async () => {
    stubFetch(() => jsonResponse({ workspace_id: Number(WORKSPACE_ID) }));

    await expect(bind()).rejects.toMatchObject({ data: { type: "unknown" } });
  });

  it("refuses a URL off the Databricks domains before calling fetch", async () => {
    const fetchMock = stubFetch(() => bindingResponse());

    await expect(
      bind({ ...workspaceRef, workspaceUrl: "https://evil.example" })
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("inBoundWorkspace", () => {
  it("binds, then calls the workspace at its URL", async () => {
    const fetchMock = stubFetch((url) =>
      isBinding(url) ? bindingResponse() : jsonResponse({ catalogs: [] })
    );

    const bound = await inBoundWorkspace(
      newDatabricksClient(accountContext()),
      workspaceRef
    );
    await bound.call({
      method: "GET",
      path: "/api/2.1/unity-catalog/catalogs",
    });

    expect(databricksCalls(fetchMock).map((call) => call.url)).toEqual([
      `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`,
      `${WORKSPACE_URL}/api/2.1/unity-catalog/catalogs`,
    ]);
  });

  it("fails without returning a client when the URL answers for another workspace", async () => {
    stubFetch(() => bindingResponse("42"));

    await expect(
      inBoundWorkspace(newDatabricksClient(accountContext()), workspaceRef)
    ).rejects.toMatchObject({ data: { type: "validation_error" } });
  });
});
