import {
  ConnectorError,
  type LogQuery,
  type LogReadResult,
  createLogger,
  newConnectorTRPC,
} from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { newAwsCloudWatchRouter } from "../router.ts";
import { NOW, fakeAws, isFreshness } from "./fake-aws.ts";
import {
  ACCOUNT,
  idcDenied,
  idcGetObject,
  idcListObjects,
  idcQuery,
  otherSession,
  row,
} from "./fixtures.ts";

const LOG_GROUP = "aws-cloudtrail-logs-org";

const callerFor = (aws: ReturnType<typeof fakeAws>) =>
  newConnectorTRPC().createCallerFactory(
    newAwsCloudWatchRouter(aws.dependencies)
  )({
    logger: createLogger(),
  })["aws-cloudwatch"];

const read = (
  aws: ReturnType<typeof fakeAws>,
  query: LogQuery = idcQuery,
  cursor?: string
) =>
  callerFor(aws).logs.read({
    query,
    logGroupName: LOG_GROUP,
    ...(cursor ? { cursor } : {}),
  });

const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("aws-cloudwatch router", () => {
  it("exposes install validation, metadata and logs, and no accesses", () => {
    expect(
      Object.keys(newAwsCloudWatchRouter()._def.procedures).sort()
    ).toEqual([
      "aws-cloudwatch.install.validation.get",
      "aws-cloudwatch.logs.check",
      "aws-cloudwatch.logs.read",
      "aws-cloudwatch.metadata.get",
    ]);
  });
});

describe("logs.read for cloudtrail", () => {
  it("reads one slice, narrows it, and returns done", async () => {
    const aws = fakeAws(() => [
      row(idcGetObject),
      row(idcListObjects),
      row(idcDenied),
      row(otherSession),
      { "@timestamp": "x", "@message": "not an event" },
    ]);
    const result = await read(aws);
    expect(result.state).toBe("done");
    expect(result.cursor).toBeUndefined();
    expect(result.entries.map((e) => e.id)).toEqual([
      idcGetObject.eventID,
      idcListObjects.eventID,
    ]);
    expect(result.gaps).toEqual([]);
    const [query] = aws.queries;
    expect(query).toMatchObject({
      logGroupName: LOG_GROUP,
      startTime: Date.parse(idcQuery.window.start) / 1000,
      endTime: Date.parse(idcQuery.window.end) / 1000,
    });
    expect(query!.queryString).toContain(`recipientAccountId = "${ACCOUNT}"`);
  });

  it("returns running with a cursor, then the entries when the query completes", async () => {
    let ready = false;
    const aws = fakeAws(() => (ready ? [row(idcGetObject)] : "running"));
    const first = await read(aws);
    expect(first).toMatchObject({ state: "running", entries: [], gaps: [] });
    expect(first.cursor).toBeDefined();

    ready = true;
    const second = await read(aws, idcQuery, first.cursor);
    expect(second.state).toBe("done");
    expect(second.entries).toHaveLength(1);
    // The cursor polled the same query rather than starting another.
    expect(aws.queries).toHaveLength(1);
  });

  it("splits a slice that fills the 10,000-row cap and reads both halves", async () => {
    const start = Date.parse(idcQuery.window.start) / 1000;
    const end = Date.parse(idcQuery.window.end) / 1000;
    const mid = (start + end) / 2;
    const aws = fakeAws((q) =>
      q.startTime === start && q.endTime === end
        ? Array.from({ length: 10_000 }, () => row(otherSession))
        : q.startTime === start
          ? [row(idcGetObject)]
          : [row({ ...idcListObjects, eventTime: "2026-11-01T12:00:00Z" })]
    );
    const first = await read(aws);
    expect(first.state).toBe("more");
    expect(first.entries.map((e) => e.id)).toEqual([idcGetObject.eventID]);
    expect(aws.queries.map((q) => [q.startTime, q.endTime])).toEqual([
      [start, end],
      [start, mid],
      [mid, end],
    ]);

    const second = await read(aws, idcQuery, first.cursor);
    expect(second.state).toBe("done");
    expect(second.entries.map((e) => e.id)).toEqual([idcListObjects.eventID]);
    expect(second.gaps).toEqual([]);
  });

  it("reports truncated when a minute-long slice still overflows", async () => {
    const query: LogQuery = {
      ...idcQuery,
      window: { start: "2026-11-01T10:15:00Z", end: "2026-11-01T10:16:00Z" },
    };
    const aws = fakeAws(() =>
      Array.from({ length: 10_000 }, () => row(idcGetObject))
    );
    const result = await read(aws, query);
    expect(aws.queries).toHaveLength(1);
    expect(result.state).toBe("done");
    expect(result.gaps).toEqual([
      expect.objectContaining({
        kind: "truncated",
        start: "2026-11-01T10:15:00.000Z",
        end: "2026-11-01T10:16:00.000Z",
      }),
    ]);
  });

  it("reports a missing log group as not delivered", async () => {
    const aws = fakeAws();
    aws.on("DescribeLogGroupsCommand", () => ({ logGroups: [] }));
    const result = await read(aws);
    expect(result).toMatchObject({ state: "done", entries: [] });
    expect(result.gaps).toEqual([
      expect.objectContaining({ kind: "not-delivered", log: "cloudtrail" }),
    ]);
    expect(aws.queries).toHaveLength(0);
  });

  it("reports retention when the window starts before the group keeps", async () => {
    const aws = fakeAws(() => []);
    aws.on("DescribeLogGroupsCommand", () => ({
      logGroups: [{ logGroupName: LOG_GROUP, retentionInDays: 1 }],
    }));
    const result: LogReadResult = await read(aws, {
      ...idcQuery,
      window: { start: "2026-10-30T00:00:00Z", end: "2026-11-01T12:00:00Z" },
    });
    expect(result.gaps).toEqual([
      expect.objectContaining({
        kind: "retention",
        retainedFrom: new Date(NOW - 86_400_000).toISOString(),
      }),
    ]);
  });

  it("reports lag with checkedThrough for a window reaching now", async () => {
    const latest = NOW - 4 * 60_000;
    const aws = fakeAws((q) =>
      isFreshness(q) ? [{ latest: String(latest) }] : [row(idcGetObject)]
    );
    const result = await read(aws, {
      ...idcQuery,
      window: {
        start: idcQuery.window.start,
        end: new Date(NOW).toISOString(),
      },
    });
    const checkedThrough = new Date(latest).toISOString();
    expect(result.state).toBe("done");
    expect(result.checkedThrough).toBe(checkedThrough);
    expect(result.gaps).toEqual([
      expect.objectContaining({ kind: "lag", checkedThrough }),
    ]);
  });

  it("rejects a cursor from another query or outside the window", async () => {
    const aws = fakeAws(() => "running");
    const { cursor } = await read(aws);
    const other: LogQuery = { ...idcQuery, accountId: "210987654321" };
    expect((await errorOf(read(aws, other, cursor))).type).toBe(
      "validation_error"
    );
    expect(
      (
        await errorOf(
          read(aws, idcQuery, Buffer.from("{}").toString("base64url"))
        )
      ).type
    ).toBe("validation_error");
    const narrower: LogQuery = {
      ...idcQuery,
      window: { start: idcQuery.window.start, end: "2026-11-01T11:00:00Z" },
    };
    expect((await errorOf(read(aws, narrower, cursor))).type).toBe(
      "validation_error"
    );
  });

  it("needs the log group, and doesn't read phase 2 sources yet", async () => {
    const aws = fakeAws();
    const caller = callerFor(aws);
    expect((await errorOf(caller.logs.read({ query: idcQuery }))).type).toBe(
      "validation_error"
    );
    expect(
      (
        await errorOf(
          caller.logs.read({
            query: {
              source: "rds",
              window: idcQuery.window,
              accountId: ACCOUNT,
              region: "us-west-2",
              instanceId: "db-1",
              engine: "postgres",
              dbUser: "p0_alice",
            },
          })
        )
      ).type
    ).toBe("validation_error");
  });
});

describe("logs.check for cloudtrail", () => {
  const TRAIL_ARN = `arn:aws:cloudtrail:us-west-2:${ACCOUNT}:trail/org-trail`;
  const withTrail = (selectors: Record<string, unknown>) => {
    const aws = fakeAws();
    aws.on("DescribeTrailsCommand", () => ({
      trailList: [
        {
          Name: "org-trail",
          TrailARN: TRAIL_ARN,
          IsOrganizationTrail: true,
          CloudWatchLogsLogGroupArn: `arn:aws:logs:us-west-2:${ACCOUNT}:log-group:${LOG_GROUP}:*`,
        },
      ],
    }));
    aws.on("GetEventSelectorsCommand", () => selectors);
    return aws;
  };
  const check = (aws: ReturnType<typeof fakeAws>, target: LogQuery) =>
    callerFor(aws).logs.check({ target, logGroupName: LOG_GROUP });

  it("reports S3 data events the trail doesn't deliver", async () => {
    const aws = withTrail({
      EventSelectors: [
        {
          ReadWriteType: "All",
          IncludeManagementEvents: true,
          DataResources: [],
        },
      ],
    });
    expect(await check(aws, idcQuery)).toEqual({
      gaps: [
        expect.objectContaining({
          kind: "not-delivered",
          log: "cloudtrail-data-events",
          service: "s3.amazonaws.com",
        }),
      ],
    });
  });

  it("reports nothing when advanced selectors deliver them", async () => {
    const aws = withTrail({
      AdvancedEventSelectors: [
        {
          Name: "S3 data events",
          FieldSelectors: [
            { Field: "eventCategory", Equals: ["Data"] },
            { Field: "resources.type", Equals: ["AWS::S3::Object"] },
          ],
        },
      ],
    });
    expect(await check(aws, idcQuery)).toEqual({ gaps: [] });
  });

  it("doesn't look at the trail for a target that reaches no data events", async () => {
    const aws = fakeAws();
    expect(
      await check(aws, { ...idcQuery, actions: ["ec2:Describe*"] })
    ).toEqual({ gaps: [] });
    expect(await check(aws, { ...idcQuery, actions: undefined })).toEqual({
      gaps: [],
    });
    expect(aws.calls).toEqual([]);
  });

  it("reports nothing when no trail names the group", async () => {
    const aws = fakeAws();
    aws.on("DescribeTrailsCommand", () => ({ trailList: [] }));
    expect(await check(aws, idcQuery)).toEqual({ gaps: [] });
  });
});
