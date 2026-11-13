import { ConnectorError, createLogger } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { fakeAws } from "../../__tests__/fake-aws.ts";
import { ACCOUNT } from "../../__tests__/fixtures.ts";
import type { InstallInput } from "../definition.ts";
import { validateInstall } from "../handler.ts";

const LOG_GROUP = "aws-cloudtrail-logs";
const TRAIL_ARN = `arn:aws:cloudtrail:us-west-2:${ACCOUNT}:trail/main`;
const MEMBER = "210987654321";

type Setup = {
  accounts?: string[];
  trail?: { IsOrganizationTrail: boolean } | null;
  selectors?: Record<string, unknown>;
  /** Whether the sample query never finishes */
  running?: boolean;
};

const setUp = ({
  accounts = [ACCOUNT],
  trail = { IsOrganizationTrail: false },
  selectors = { EventSelectors: [{ DataResources: [] }] },
  running = false,
}: Setup = {}) => {
  const aws = fakeAws(() =>
    running
      ? "running"
      : accounts.map((account) => ({
          recipientAccountId: account,
          events: "120",
          latest: "2026-11-01 13:55:01.000",
        }))
  );
  aws.on("DescribeTrailsCommand", () => ({
    trailList: trail
      ? [
          {
            Name: "main",
            TrailARN: TRAIL_ARN,
            CloudWatchLogsLogGroupArn: `arn:aws:logs:us-west-2:${ACCOUNT}:log-group:${LOG_GROUP}:*`,
            ...trail,
          },
        ]
      : [],
  }));
  aws.on("GetEventSelectorsCommand", () => selectors);
  return aws;
};

const validate = (aws: ReturnType<typeof fakeAws>, input: InstallInput) =>
  validateInstall(input, createLogger(), aws.dependencies);

const failureOf = async (
  aws: ReturnType<typeof fakeAws>,
  input: InstallInput
) => {
  const error = await validate(aws, input).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("validateInstall", () => {
  it("passes an item without CloudTrail without calling AWS", async () => {
    const aws = setUp();
    expect(await validate(aws, {})).toEqual({ warnings: [] });
    expect(aws.calls).toEqual([]);
  });

  it("reports the group, its accounts and trail, and missing data events", async () => {
    const aws = setUp();
    const result = await validate(aws, {
      logGroupName: LOG_GROUP,
      coverage: "account",
    });
    expect(result).toEqual({
      cloudtrail: {
        logGroupName: LOG_GROUP,
        logGroupArn: `arn:aws:logs:us-west-2:123456789012:log-group:${LOG_GROUP}:*`,
        retentionInDays: 365,
        latestEventTime: "2026-11-01T13:55:01.000Z",
        accounts: [ACCOUNT],
        trail: { arn: TRAIL_ARN, name: "main", isOrganizationTrail: false },
        dataEventTypes: [],
      },
      warnings: [
        {
          check: "data_events",
          resourceTypes: [
            "AWS::S3::Object",
            "AWS::Lambda::Function",
            "AWS::DynamoDB::Table",
          ],
        },
      ],
    });
    expect(aws.queries[0]!.endTime - aws.queries[0]!.startTime).toBe(86_400);
  });

  it("fails on a missing group", async () => {
    const aws = setUp();
    aws.on("DescribeLogGroupsCommand", () => ({ logGroups: [] }));
    expect(await failureOf(aws, { logGroupName: LOG_GROUP })).toMatchObject({
      type: "object_not_found",
      payload: { step: "log_group", logGroupName: LOG_GROUP },
    });
  });

  it("fails on a group with no event in the last day", async () => {
    const aws = setUp({ accounts: [] });
    expect(await failureOf(aws, { logGroupName: LOG_GROUP })).toMatchObject({
      type: "object_not_found",
      payload: { step: "recent_events" },
    });
  });

  it("fails organization coverage on an account trail", async () => {
    const aws = setUp();
    expect(
      await failureOf(aws, {
        logGroupName: LOG_GROUP,
        coverage: "organization",
      })
    ).toMatchObject({
      type: "validation_error",
      payload: { step: "coverage" },
    });
  });

  it("judges coverage from the sampled accounts when no trail names the group", async () => {
    const one = setUp({ trail: null });
    expect(
      await failureOf(one, {
        logGroupName: LOG_GROUP,
        coverage: "organization",
      })
    ).toMatchObject({ payload: { step: "coverage" } });

    const many = setUp({ trail: null, accounts: [ACCOUNT, MEMBER] });
    const result = await validate(many, {
      logGroupName: LOG_GROUP,
      coverage: "organization",
    });
    expect(result.cloudtrail?.accounts).toEqual([MEMBER, ACCOUNT].sort());
    expect(result.warnings).toEqual([
      expect.objectContaining({ check: "trail_not_found" }),
    ]);
  });

  it("warns, not fails, when the sample doesn't finish in time", async () => {
    const aws = setUp({ running: true });
    const result = await validate(aws, {
      logGroupName: LOG_GROUP,
      coverage: "account",
    });
    expect(result.cloudtrail).not.toHaveProperty("accounts");
    expect(result.cloudtrail).not.toHaveProperty("latestEventTime");
    expect(result.warnings).toContainEqual(
      expect.objectContaining({ check: "recent_events" })
    );
  });

  it("passes organization coverage it can't judge when the sample doesn't finish and no trail names the group", async () => {
    const aws = setUp({ trail: null, running: true });
    const result = await validate(aws, {
      logGroupName: LOG_GROUP,
      coverage: "organization",
    });
    expect(result.warnings.map(({ check }) => check)).toEqual([
      "recent_events",
      "trail_not_found",
    ]);
  });

  it("warns, not fails, on an account item over an organization trail with data events", async () => {
    const aws = setUp({
      trail: { IsOrganizationTrail: true },
      selectors: {
        AdvancedEventSelectors: [
          {
            FieldSelectors: [
              { Field: "eventCategory", Equals: ["Data"] },
              {
                Field: "resources.type",
                Equals: [
                  "AWS::S3::Object",
                  "AWS::Lambda::Function",
                  "AWS::DynamoDB::Table",
                ],
              },
            ],
          },
        ],
      },
    });
    const result = await validate(aws, { logGroupName: LOG_GROUP });
    expect(result.warnings).toEqual([
      expect.objectContaining({ check: "coverage" }),
    ]);
    expect(result.cloudtrail?.dataEventTypes).toHaveLength(3);
  });

  it("maps an access failure to its step", async () => {
    const aws = setUp();
    aws.on("DescribeTrailsCommand", () => {
      throw Object.assign(new Error("not authorized"), {
        name: "AccessDeniedException",
      });
    });
    expect(await failureOf(aws, { logGroupName: LOG_GROUP })).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "coverage" },
    });
  });
});
