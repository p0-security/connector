/**
 * How IAM action names line up with CloudTrail's `eventSource` and
 * `eventName`. They mostly agree (`s3:GetObject` is `GetObject` from
 * `s3.amazonaws.com`); the tables here hold the exceptions that matter for
 * narrowing.
 */

/** Services whose `eventSource` isn't `<IAM prefix>.amazonaws.com`. */
const EVENT_SOURCE_PREFIXES: Record<string, string> = {
  "monitoring.amazonaws.com": "cloudwatch",
};

const PREFIX_EVENT_SOURCES = Object.fromEntries(
  Object.entries(EVENT_SOURCE_PREFIXES).map(([source, prefix]) => [
    prefix,
    source,
  ])
);

/**
 * IAM prefixes whose `eventSource` is known, so a filter on it can be pushed
 * into the Logs Insights query without dropping events. Any other prefix is
 * narrowed in the connector only.
 */
const PUSHDOWN_PREFIXES = new Set([
  "apigateway",
  "athena",
  "autoscaling",
  "bedrock",
  "cloudformation",
  "cloudtrail",
  "cloudwatch",
  "dynamodb",
  "ec2",
  "ecr",
  "ecs",
  "eks",
  "elasticloadbalancing",
  "events",
  "firehose",
  "glue",
  "iam",
  "kinesis",
  "kms",
  "lambda",
  "logs",
  "rds",
  "redshift",
  "route53",
  "s3",
  "sagemaker",
  "secretsmanager",
  "sns",
  "sqs",
  "ssm",
  "states",
  "sts",
]);

/** The IAM service prefix of a CloudTrail `eventSource`. */
export const servicePrefix = (eventSource: string) =>
  EVENT_SOURCE_PREFIXES[eventSource] ??
  eventSource.replace(/\.amazonaws\.com$/, "");

/** The CloudTrail `eventSource` of an IAM service prefix. */
export const eventSourceFor = (prefix: string) =>
  PREFIX_EVENT_SOURCES[prefix] ?? `${prefix}.amazonaws.com`;

/**
 * The `eventSource`s to filter on for a set of IAM action patterns, or
 * undefined when any pattern's service can't be pinned down (a wildcard in
 * the prefix, or a service not in {@link PUSHDOWN_PREFIXES}).
 */
export const pushdownEventSources = (actions: readonly string[]) => {
  const sources = new Set<string>();
  for (const action of actions) {
    const prefix = action.split(":")[0]!.toLowerCase();
    if (!PUSHDOWN_PREFIXES.has(prefix)) return undefined;
    sources.add(eventSourceFor(prefix));
  }
  return [...sources].sort();
};

/**
 * CloudTrail event names that are authorized by a differently named IAM
 * action, keyed by `prefix:eventName`.
 */
const ACTION_ALIASES: Record<string, string[]> = {
  "s3:ListObjects": ["s3:ListBucket"],
  "s3:ListObjectsV2": ["s3:ListBucket"],
  "s3:ListObjectVersions": ["s3:ListBucketVersions"],
  "s3:HeadBucket": ["s3:ListBucket"],
  "s3:HeadObject": ["s3:GetObject"],
  "s3:ListBuckets": ["s3:ListAllMyBuckets"],
  "s3:CopyObject": ["s3:PutObject", "s3:GetObject"],
  "s3:CreateMultipartUpload": ["s3:PutObject"],
  "s3:UploadPart": ["s3:PutObject"],
  "s3:UploadPartCopy": ["s3:PutObject", "s3:GetObject"],
  "s3:CompleteMultipartUpload": ["s3:PutObject"],
  "s3:DeleteObjects": ["s3:DeleteObject"],
  "lambda:Invoke": ["lambda:InvokeFunction"],
};

/**
 * The IAM action a CloudTrail event is, plus the IAM actions that authorize
 * it when they're named differently. Lambda's API-version suffix
 * (`GetFunction20150331v2`) is dropped.
 */
export const eventActions = (eventSource: string, eventName: string) => {
  const prefix = servicePrefix(eventSource);
  const name =
    prefix === "lambda" ? eventName.replace(/\d{8}(v\d+)?$/, "") : eventName;
  const action = `${prefix}:${name}`;
  return { action, authorizedBy: [action, ...(ACTION_ALIASES[action] ?? [])] };
};

/**
 * Data events a trail can deliver, by the resource type its event selectors
 * name, and which actions they hold. A grant whose actions reach one of
 * these services sees nothing of it unless the trail delivers that type.
 */
export const DATA_EVENT_TYPES = [
  {
    resourceType: "AWS::S3::Object",
    eventSource: "s3.amazonaws.com",
    label: "S3",
    prefix: "s3",
    actions: /.*/,
  },
  {
    resourceType: "AWS::Lambda::Function",
    eventSource: "lambda.amazonaws.com",
    label: "Lambda",
    prefix: "lambda",
    actions: /^invoke/i,
  },
  {
    resourceType: "AWS::DynamoDB::Table",
    eventSource: "dynamodb.amazonaws.com",
    label: "DynamoDB",
    prefix: "dynamodb",
    actions: /.*/,
  },
] as const;
