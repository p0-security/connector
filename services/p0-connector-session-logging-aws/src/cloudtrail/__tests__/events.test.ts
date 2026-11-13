import { LogEntrySchema } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  ACCOUNT,
  federatedDescribeInstances,
  federatedQuery,
  iamUserCreateKey,
  iamUserQuery,
  idcDenied,
  idcGetObject,
  idcListObjects,
  idcQuery,
  otherSession,
} from "../../__tests__/fixtures.ts";
import {
  type CloudTrailEvent,
  eventMatches,
  parseEvent,
  toLogEntry,
} from "../events.ts";

const window = {
  start: Date.parse(idcQuery.window.start),
  end: Date.parse(idcQuery.window.end),
};

describe("toLogEntry", () => {
  it("normalizes an Identity Center data event", () => {
    const entry = toLogEntry(idcGetObject);
    expect(entry).toEqual({
      id: idcGetObject.eventID,
      time: "2026-11-01T10:15:42.000Z",
      action: "s3:GetObject",
      resource: "arn:aws:s3:::acme-reports/2026/q3.csv",
      result: "allowed",
      principal: idcGetObject.userIdentity!.arn,
      raw: idcGetObject,
    });
    expect(LogEntrySchema.parse(entry)).toEqual(entry);
  });

  it("marks access-denied errors as denied", () => {
    expect(toLogEntry(idcDenied).result).toBe("denied");
    expect(
      toLogEntry({
        ...federatedDescribeInstances,
        errorCode: "Client.UnauthorizedOperation",
      }).result
    ).toBe("denied");
    expect(toLogEntry({ ...idcGetObject, errorCode: "NoSuchKey" }).result).toBe(
      "allowed"
    );
  });

  it("takes the resource from the request when an event lists none", () => {
    const { resources: _, ...noResources } = idcGetObject;
    expect(toLogEntry(noResources as CloudTrailEvent).resource).toBe(
      "arn:aws:s3:::acme-reports/2026/q3.csv"
    );
    expect(toLogEntry(federatedDescribeInstances).resource).toBeUndefined();
  });

  it("derives a request's S3 ARN in the caller's partition", () => {
    const { resources: _, ...noResources } = idcGetObject;
    const govCloud = {
      ...noResources,
      userIdentity: {
        ...idcGetObject.userIdentity,
        arn: idcGetObject.userIdentity!.arn!.replace(
          "arn:aws:",
          "arn:aws-us-gov:"
        ),
      },
    } as CloudTrailEvent;
    expect(toLogEntry(govCloud).resource).toBe(
      "arn:aws-us-gov:s3:::acme-reports/2026/q3.csv"
    );
  });

  it("names IAM user and federated actions", () => {
    expect(toLogEntry(iamUserCreateKey)).toMatchObject({
      action: "kms:Decrypt",
      principal: iamUserCreateKey.userIdentity!.arn,
    });
    expect(toLogEntry(federatedDescribeInstances).action).toBe(
      "ec2:DescribeInstances"
    );
  });

  it("drops Lambda's API-version suffix", () => {
    expect(
      toLogEntry({
        ...iamUserCreateKey,
        eventSource: "lambda.amazonaws.com",
        eventName: "GetFunction20150331v2",
      }).action
    ).toBe("lambda:GetFunction");
  });
});

describe("parseEvent", () => {
  it("parses a CloudTrail event and rejects anything else", () => {
    expect(parseEvent(JSON.stringify(idcGetObject))).toEqual(idcGetObject);
    expect(parseEvent("not json")).toBeUndefined();
    expect(parseEvent(JSON.stringify({ message: "hi" }))).toBeUndefined();
  });
});

describe("eventMatches", () => {
  it("keeps the grant's own actions on its resources", () => {
    expect(eventMatches(idcQuery, idcGetObject, window)).toBe(true);
    // ListObjectsV2 is authorized by s3:ListBucket.
    expect(eventMatches(idcQuery, idcListObjects, window)).toBe(true);
  });

  it("drops another session, account, action, resource or time", () => {
    expect(eventMatches(idcQuery, otherSession, window)).toBe(false);
    expect(
      eventMatches(
        idcQuery,
        { ...idcGetObject, recipientAccountId: "210987654321" },
        window
      )
    ).toBe(false);
    // PutObject isn't among the granted actions.
    expect(eventMatches(idcQuery, idcDenied, window)).toBe(false);
    expect(
      eventMatches(
        idcQuery,
        {
          ...idcGetObject,
          resources: [{ type: "AWS::S3::Object", ARN: "arn:aws:s3:::other/x" }],
        },
        window
      )
    ).toBe(false);
    expect(
      eventMatches(idcQuery, idcGetObject, {
        start: window.start,
        end: Date.parse(idcGetObject.eventTime!),
      })
    ).toBe(false);
  });

  it("checks an S3 object call against its object, not its bucket", () => {
    // ListBucket on the bucket, GetObject only under allowed/.
    const query = {
      ...idcQuery,
      resources: [
        "arn:aws:s3:::acme-reports",
        "arn:aws:s3:::acme-reports/allowed/*",
      ],
    };
    expect(eventMatches(query, idcGetObject, window)).toBe(false);
    expect(
      eventMatches(
        query,
        {
          ...idcGetObject,
          resources: [
            {
              type: "AWS::S3::Object",
              ARN: "arn:aws:s3:::acme-reports/allowed/x",
            },
            { type: "AWS::S3::Bucket", ARN: "arn:aws:s3:::acme-reports" },
          ],
        },
        window
      )
    ).toBe(true);
    // A bucket-level call is still checked against the bucket.
    expect(eventMatches(query, idcListObjects, window)).toBe(true);
  });

  it("authorizes renamed operations by their IAM action", () => {
    expect(
      eventMatches(
        { ...idcQuery, actions: ["s3:GetObject"] },
        { ...idcGetObject, eventName: "SelectObjectContent" },
        window
      )
    ).toBe(true);
    const getRestApis = {
      ...federatedDescribeInstances,
      eventSource: "apigateway.amazonaws.com",
      eventName: "GetRestApis",
    };
    expect(
      eventMatches(
        { ...federatedQuery, actions: ["apigateway:GET"] },
        getRestApis,
        window
      )
    ).toBe(true);
    expect(
      eventMatches(
        { ...federatedQuery, actions: ["apigateway:DELETE"] },
        getRestApis,
        window
      )
    ).toBe(false);
  });

  it("matches IAM action patterns case-insensitively", () => {
    expect(
      eventMatches(
        { ...federatedQuery, actions: ["EC2:describe*"] },
        federatedDescribeInstances,
        window
      )
    ).toBe(true);
    expect(
      eventMatches(
        { ...federatedQuery, actions: ["ec2:Run*"] },
        federatedDescribeInstances,
        window
      )
    ).toBe(false);
  });

  it("keeps an event with no resource ARN to check", () => {
    expect(
      eventMatches(
        { ...federatedQuery, resources: ["arn:aws:ec2:*:*:instance/i-1"] },
        federatedDescribeInstances,
        window
      )
    ).toBe(true);
  });

  it("matches a source identity only with its role", () => {
    expect(
      eventMatches(federatedQuery, federatedDescribeInstances, window)
    ).toBe(true);
    expect(
      eventMatches(
        {
          ...federatedQuery,
          identity: { kind: "source-identity", value: "eve@example.com" },
        },
        federatedDescribeInstances,
        window
      )
    ).toBe(false);
    expect(
      eventMatches(
        {
          ...federatedQuery,
          identity: {
            kind: "source-identity",
            value: "bob@example.com",
            roleName: "Other",
          },
        },
        federatedDescribeInstances,
        window
      )
    ).toBe(false);
  });

  it("matches an IAM user by name and account", () => {
    expect(eventMatches(iamUserQuery, iamUserCreateKey, window)).toBe(true);
    expect(eventMatches(iamUserQuery, idcGetObject, window)).toBe(false);
  });

  it("matches an IAM user with a path from an ARN without it", () => {
    const withPath = {
      ...iamUserCreateKey,
      userIdentity: {
        ...iamUserCreateKey.userIdentity,
        arn: `arn:aws:iam::${ACCOUNT}:user/engineering/p0-carol`,
      },
    };
    expect(eventMatches(iamUserQuery, withPath, window)).toBe(true);
  });

  it("doesn't match a same-named user from another account", () => {
    const otherAccount = {
      ...iamUserCreateKey,
      userIdentity: {
        ...iamUserCreateKey.userIdentity,
        arn: "arn:aws:iam::999999999999:user/p0-carol",
        accountId: "999999999999",
      },
    };
    expect(eventMatches(iamUserQuery, otherAccount, window)).toBe(false);
  });
});
