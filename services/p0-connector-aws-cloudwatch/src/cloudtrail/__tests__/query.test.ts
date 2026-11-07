import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  ACCOUNT,
  federatedQuery,
  iamUserQuery,
  idcQuery,
} from "../../__tests__/fixtures.ts";
import { composeInsightsQuery } from "../query.ts";
import { pushdownEventSources } from "../services.ts";

describe("composeInsightsQuery", () => {
  it("matches an Identity Center session by role pattern and session name", () => {
    expect(composeInsightsQuery(idcQuery)).toBe(
      [
        "fields @timestamp, @message",
        `| filter recipientAccountId = "${ACCOUNT}"`,
        `| filter userIdentity.arn =~ /(?i)^arn:aws[a-z-]*:sts::${ACCOUNT}:assumed-role\\/AWSReservedSSO_P0Grant_7f3a9c_[^/]*\\/alice@example\\.com$/`,
        '| filter eventSource in ["s3.amazonaws.com"]',
        "| limit 10000",
      ].join("\n")
    );
  });

  it("matches an exact role name with any session", () => {
    const query = composeInsightsQuery({
      ...idcQuery,
      identity: { kind: "assumed-role", roleName: "P0Role.v2" },
      actions: undefined,
    });
    expect(query).toContain(`assumed-role\\/P0Role\\.v2\\/[^/]+$/`);
    expect(query).not.toContain("eventSource");
  });

  it("matches a pooled role by source identity", () => {
    const query = composeInsightsQuery(federatedQuery);
    expect(query).toContain(
      'userIdentity.sessionContext.sourceIdentity = "bob@example.com"'
    );
    expect(query).toContain(`assumed-role\\/P0GrantPool\\/[^/]+$/`);
    expect(query).toContain('eventSource in ["ec2.amazonaws.com"]');
  });

  it("matches an IAM user by ARN", () => {
    expect(composeInsightsQuery(iamUserQuery)).toBe(
      [
        "fields @timestamp, @message",
        `| filter recipientAccountId = "${ACCOUNT}"`,
        `| filter userIdentity.arn = "arn:aws:iam::${ACCOUNT}:user/p0-carol"`,
        "| limit 10000",
      ].join("\n")
    );
  });

  it("escapes quotes and regex syntax and refuses line breaks", () => {
    const query = composeInsightsQuery({
      ...federatedQuery,
      identity: { kind: "source-identity", value: 'a"b\\c' },
    });
    expect(query).toContain(
      'userIdentity.sessionContext.sourceIdentity = "a\\"b\\\\c"'
    );
    expect(() =>
      composeInsightsQuery({
        ...federatedQuery,
        identity: { kind: "source-identity", value: "a\n| limit 1" },
      })
    ).toThrow(ConnectorError);
    expect(
      composeInsightsQuery({
        ...idcQuery,
        identity: {
          kind: "assumed-role",
          roleName: "r",
          sessionName: "x/.*",
        },
      })
    ).toContain("\\/r\\/x\\/\\.\\*$/");
  });
});

describe("pushdownEventSources", () => {
  it("names each service once, and gives up on wildcards and unknown services", () => {
    expect(
      pushdownEventSources(["s3:GetObject", "s3:Put*", "cloudwatch:Get*"])
    ).toEqual(["monitoring.amazonaws.com", "s3.amazonaws.com"]);
    expect(pushdownEventSources(["*"])).toBeUndefined();
    expect(pushdownEventSources(["s3*:Get*"])).toBeUndefined();
    expect(pushdownEventSources(["execute-api:Invoke"])).toBeUndefined();
  });
});
