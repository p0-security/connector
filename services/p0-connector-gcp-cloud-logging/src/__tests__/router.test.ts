import {
  ConnectorError,
  type LogQuery,
  createLogger,
  newConnectorTRPC,
} from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { newGcpCloudLoggingRouter } from "../router.ts";
import { NOW, fakeLogging, throttled } from "./fake-logging.ts";
import {
  PROJECT,
  adminActivity,
  bucketQuery,
  dataAccess,
  denied,
  impersonated,
  otherPrincipal,
  projectQuery,
} from "./fixtures.ts";

const callerFor = (logging: ReturnType<typeof fakeLogging>) =>
  newConnectorTRPC().createCallerFactory(
    newGcpCloudLoggingRouter(logging.dependencies)
  )({
    logger: createLogger(),
  })["gcp-cloud-logging"];

const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("gcp-cloud-logging router", () => {
  it("exposes install validation, metadata and logs, and no accesses", () => {
    expect(
      Object.keys(newGcpCloudLoggingRouter()._def.procedures).sort()
    ).toEqual([
      "gcp-cloud-logging.install.validation.get",
      "gcp-cloud-logging.logs.check",
      "gcp-cloud-logging.logs.read",
      "gcp-cloud-logging.metadata.get",
    ]);
  });
});

describe("logs.read for gcp-audit", () => {
  it("reads a page of the project's audit logs, narrowed", async () => {
    const logging = fakeLogging(() => ({
      entries: [
        adminActivity,
        dataAccess,
        denied,
        impersonated,
        otherPrincipal,
      ],
    }));
    const result = await callerFor(logging).logs.read({ query: projectQuery });
    expect(result.state).toBe("done");
    expect(result.entries.map((e) => e.id)).toEqual([
      adminActivity.insertId,
      dataAccess.insertId,
      denied.insertId,
      impersonated.insertId,
    ]);
    expect(result.gaps).toEqual([]);
    expect(logging.requests).toEqual([
      expect.objectContaining({
        resourceNames: [`projects/${PROJECT}`],
        orderBy: "timestamp asc",
        pageSize: 1000,
      }),
    ]);
  });

  it("pages with the page token as cursor", async () => {
    const logging = fakeLogging((request) =>
      request.pageToken === undefined
        ? { entries: [dataAccess], nextPageToken: "page-2" }
        : { entries: [impersonated] }
    );
    const caller = callerFor(logging);
    const first = await caller.logs.read({ query: bucketQuery });
    expect(first.state).toBe("more");
    expect(first.entries.map((e) => e.id)).toEqual([dataAccess.insertId]);

    const second = await caller.logs.read({
      query: bucketQuery,
      cursor: first.cursor!,
    });
    expect(logging.requests[1]!.pageToken).toBe("page-2");
    expect(second.state).toBe("done");
    // Impersonated bucket listing is outside the bucket grant's permissions.
    expect(second.entries).toEqual([]);
  });

  it("keeps paging past empty pages, up to three per call", async () => {
    let page = 0;
    const logging = fakeLogging(() => ({
      entries: [],
      nextPageToken: `page-${++page + 1}`,
    }));
    const result = await callerFor(logging).logs.read({ query: bucketQuery });
    expect(logging.requests).toHaveLength(3);
    expect(result.state).toBe("more");
  });

  it("backs off on 429 and returns what it has when the budget runs out", async () => {
    let calls = 0;
    const logging = fakeLogging(() => {
      calls++;
      if (calls === 1) throw throttled();
      if (calls === 2) return { entries: [], nextPageToken: "page-2" };
      throw throttled();
    });
    const result = await callerFor(logging).logs.read({ query: bucketQuery });
    expect(result.state).toBe("more");
    expect(result.entries).toEqual([]);
    const resumed = fakeLogging(() => ({ entries: [dataAccess] }));
    const next = await callerFor(resumed).logs.read({
      query: bucketQuery,
      cursor: result.cursor!,
    });
    expect(resumed.requests[0]!.pageToken).toBe("page-2");
    expect(next.entries).toHaveLength(1);
  });

  it("maps a refusal to insufficient_privileges", async () => {
    const logging = fakeLogging(() => {
      throw Object.assign(new Error("Permission denied"), {
        response: { status: 403 },
      });
    });
    expect(
      (await errorOf(callerFor(logging).logs.read({ query: bucketQuery }))).type
    ).toBe("insufficient_privileges");
  });

  it("reports retention past 30 days and lag for a live window", async () => {
    const logging = fakeLogging(() => ({ entries: [] }));
    const result = await callerFor(logging).logs.read({
      query: {
        ...bucketQuery,
        window: {
          start: "2026-09-01T00:00:00Z",
          end: new Date(NOW).toISOString(),
        },
      },
    });
    expect(result.gaps.map((g) => g.kind)).toEqual(["retention", "lag"]);
  });

  it("rejects a cursor from another query", async () => {
    const logging = fakeLogging(() => ({
      entries: [dataAccess],
      nextPageToken: "page-2",
    }));
    const caller = callerFor(logging);
    const { cursor } = await caller.logs.read({ query: bucketQuery });
    expect(
      (
        await errorOf(
          caller.logs.read({
            query: { ...bucketQuery, principalEmail: "mallory@example.com" },
            cursor: cursor!,
          })
        )
      ).type
    ).toBe("validation_error");
  });

  it("checks nothing for gcp-audit and rejects AWS sources", async () => {
    const logging = fakeLogging(() => ({}));
    const caller = callerFor(logging);
    expect(await caller.logs.check({ target: bucketQuery })).toEqual({
      gaps: [],
    });
    const cloudtrail: LogQuery = {
      source: "cloudtrail",
      window: bucketQuery.window,
      accountId: "123456789012",
      identity: {
        kind: "iam-user",
        userArn: "arn:aws:iam::123456789012:user/x",
      },
    };
    expect((await errorOf(caller.logs.read({ query: cloudtrail }))).type).toBe(
      "validation_error"
    );
  });
});

describe("install.validation.get", () => {
  it("lists one Data Access entry from the project", async () => {
    const logging = fakeLogging(() => ({ entries: [] }));
    expect(
      await callerFor(logging).install.validation.get({ projectId: PROJECT })
    ).toEqual({ projectId: PROJECT, warnings: [] });
    expect(logging.requests[0]).toMatchObject({
      resourceNames: [`projects/${PROJECT}`],
      pageSize: 1,
    });
    expect(logging.requests[0]!.filter).toContain("%2Fdata_access");
  });

  it("fails at read_logs without permission", async () => {
    const logging = fakeLogging(() => {
      throw Object.assign(new Error("Permission denied"), {
        response: { status: 403 },
      });
    });
    expect(
      await errorOf(
        callerFor(logging).install.validation.get({ projectId: PROJECT })
      )
    ).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "read_logs", projectId: PROJECT },
    });
  });
});
