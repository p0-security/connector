import type { CloudTrailLogQuery } from "@p0security/connector-core";

import type { CloudTrailEvent } from "../cloudtrail/events.ts";

/**
 * CloudTrail events as CloudTrail delivers them to CloudWatch Logs (one JSON
 * object per log event), modelled on recorded events with identifiers
 * replaced.
 */
export const ACCOUNT = "123456789012";

/** An S3 data event from an Identity Center session of a per-request permission set. */
export const idcGetObject: CloudTrailEvent = {
  eventVersion: "1.09",
  userIdentity: {
    type: "AssumedRole",
    principalId: "AROA3EXAMPLEIDC1:alice@example.com",
    arn: `arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_P0Grant_7f3a9c_1a2b3c4d5e6f7a8b/alice@example.com`,
    accountId: ACCOUNT,
    accessKeyId: "ASIA3EXAMPLEKEY0001",
    sessionContext: {
      sessionIssuer: {
        type: "Role",
        principalId: "AROA3EXAMPLEIDC1",
        arn: `arn:aws:iam::${ACCOUNT}:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_P0Grant_7f3a9c_1a2b3c4d5e6f7a8b`,
        accountId: ACCOUNT,
        userName: "AWSReservedSSO_P0Grant_7f3a9c_1a2b3c4d5e6f7a8b",
      },
      attributes: {
        creationDate: "2026-11-01T10:01:12Z",
        mfaAuthenticated: "false",
      },
    },
  },
  eventTime: "2026-11-01T10:15:42Z",
  eventSource: "s3.amazonaws.com",
  eventName: "GetObject",
  awsRegion: "us-west-2",
  sourceIPAddress: "203.0.113.10",
  userAgent: "[aws-cli/2.17.0 md/awscrt#0.20.11 ua/2.0 os/macos#24.1.0]",
  requestParameters: {
    bucketName: "acme-reports",
    Host: "acme-reports.s3.us-west-2.amazonaws.com",
    key: "2026/q3.csv",
  },
  responseElements: null,
  additionalEventData: { bytesTransferredOut: 52311 },
  requestID: "C3D13FE58DE4C810",
  eventID: "6c0f6a5e-3b4e-4d2a-9b1f-0e8f2f7d1a01",
  readOnly: true,
  resources: [
    {
      type: "AWS::S3::Object",
      ARN: "arn:aws:s3:::acme-reports/2026/q3.csv",
    },
    {
      accountId: ACCOUNT,
      type: "AWS::S3::Bucket",
      ARN: "arn:aws:s3:::acme-reports",
    },
  ],
  eventType: "AwsApiCall",
  managementEvent: false,
  recipientAccountId: ACCOUNT,
  eventCategory: "Data",
};

/** The same session listing the bucket: IAM calls it s3:ListBucket. */
export const idcListObjects: CloudTrailEvent = {
  ...idcGetObject,
  eventTime: "2026-11-01T10:14:03Z",
  eventName: "ListObjectsV2",
  requestParameters: { bucketName: "acme-reports", "list-type": "2" },
  eventID: "6c0f6a5e-3b4e-4d2a-9b1f-0e8f2f7d1a02",
  resources: [
    {
      accountId: ACCOUNT,
      type: "AWS::S3::Bucket",
      ARN: "arn:aws:s3:::acme-reports",
    },
  ],
};

/** The same session refused on another bucket. */
export const idcDenied: CloudTrailEvent = {
  ...idcGetObject,
  eventTime: "2026-11-01T10:16:30Z",
  eventName: "PutObject",
  errorCode: "AccessDenied",
  errorMessage:
    "User: arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_P0Grant_7f3a9c_1a2b3c4d5e6f7a8b/alice@example.com is not authorized to perform: s3:PutObject",
  requestParameters: { bucketName: "acme-reports", key: "2026/q4.csv" },
  eventID: "6c0f6a5e-3b4e-4d2a-9b1f-0e8f2f7d1a03",
  readOnly: false,
  resources: [
    {
      type: "AWS::S3::Object",
      ARN: "arn:aws:s3:::acme-reports/2026/q4.csv",
    },
  ],
};

/** A management event from a pooled federated role, tagged with a source identity. */
export const federatedDescribeInstances: CloudTrailEvent = {
  eventVersion: "1.10",
  userIdentity: {
    type: "AssumedRole",
    principalId: "AROA3EXAMPLEFED1:okta-session-81",
    arn: `arn:aws:sts::${ACCOUNT}:assumed-role/P0GrantPool/okta-session-81`,
    accountId: ACCOUNT,
    accessKeyId: "ASIA3EXAMPLEKEY0002",
    sessionContext: {
      sessionIssuer: {
        type: "Role",
        principalId: "AROA3EXAMPLEFED1",
        arn: `arn:aws:iam::${ACCOUNT}:role/P0GrantPool`,
        accountId: ACCOUNT,
        userName: "P0GrantPool",
      },
      attributes: {
        creationDate: "2026-11-01T11:00:00Z",
        mfaAuthenticated: "false",
      },
      sourceIdentity: "bob@example.com",
    },
  },
  eventTime: "2026-11-01T11:02:10Z",
  eventSource: "ec2.amazonaws.com",
  eventName: "DescribeInstances",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-sdk-go-v2/1.30.0",
  requestParameters: {
    instancesSet: {},
    filterSet: {},
  },
  responseElements: null,
  requestID: "5b1f2a1e-7c4d-4f1e-8a3b-2f6e9d0c1b11",
  eventID: "a1b2c3d4-0000-4000-8000-000000000011",
  readOnly: true,
  eventType: "AwsApiCall",
  managementEvent: true,
  recipientAccountId: ACCOUNT,
  eventCategory: "Management",
};

/** An IAM user's own call. */
export const iamUserCreateKey: CloudTrailEvent = {
  eventVersion: "1.09",
  userIdentity: {
    type: "IAMUser",
    principalId: "AIDA3EXAMPLEUSER01",
    arn: `arn:aws:iam::${ACCOUNT}:user/p0-carol`,
    accountId: ACCOUNT,
    accessKeyId: "AKIA3EXAMPLEKEY0003",
    userName: "p0-carol",
  },
  eventTime: "2026-11-01T12:30:00Z",
  eventSource: "kms.amazonaws.com",
  eventName: "Decrypt",
  awsRegion: "us-west-2",
  sourceIPAddress: "192.0.2.44",
  userAgent: "aws-cli/2.17.0",
  requestParameters: {
    encryptionAlgorithm: "SYMMETRIC_DEFAULT",
  },
  responseElements: null,
  requestID: "e2b6f9b0-4a1d-4c3e-9f8a-7b6c5d4e3f21",
  eventID: "f0e1d2c3-0000-4000-8000-000000000021",
  readOnly: true,
  resources: [
    {
      accountId: ACCOUNT,
      type: "AWS::KMS::Key",
      ARN: `arn:aws:kms:us-west-2:${ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab`,
    },
  ],
  eventType: "AwsApiCall",
  managementEvent: false,
  recipientAccountId: ACCOUNT,
  eventCategory: "Data",
};

/** Someone else's session in the same account, which must never come back. */
export const otherSession: CloudTrailEvent = {
  ...idcGetObject,
  userIdentity: {
    ...idcGetObject.userIdentity,
    arn: `arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_P0Grant_7f3a9c_1a2b3c4d5e6f7a8b/mallory@example.com`,
  },
  eventID: "6c0f6a5e-3b4e-4d2a-9b1f-0e8f2f7d1a99",
};

export const window = {
  start: "2026-11-01T10:00:00Z",
  end: "2026-11-01T13:00:00Z",
};

export const idcQuery: CloudTrailLogQuery = {
  source: "cloudtrail",
  window,
  accountId: ACCOUNT,
  identity: {
    kind: "assumed-role",
    roleNamePattern: "AWSReservedSSO_P0Grant_7f3a9c_*",
    sessionName: "alice@example.com",
  },
  actions: ["s3:GetObject", "s3:ListBucket"],
  resources: ["arn:aws:s3:::acme-reports", "arn:aws:s3:::acme-reports/*"],
};

export const federatedQuery: CloudTrailLogQuery = {
  source: "cloudtrail",
  window,
  accountId: ACCOUNT,
  identity: {
    kind: "source-identity",
    value: "bob@example.com",
    roleName: "P0GrantPool",
  },
  actions: ["ec2:Describe*"],
  resources: ["*"],
};

export const iamUserQuery: CloudTrailLogQuery = {
  source: "cloudtrail",
  window,
  accountId: ACCOUNT,
  identity: {
    kind: "iam-user",
    userArn: `arn:aws:iam::${ACCOUNT}:user/p0-carol`,
  },
};

/** An Insights result row for an event, as `fields @timestamp, @message` returns it. */
export const row = (event: CloudTrailEvent) => ({
  "@timestamp": event.eventTime!.replace("T", " ").replace("Z", ".000"),
  "@message": JSON.stringify(event),
});
