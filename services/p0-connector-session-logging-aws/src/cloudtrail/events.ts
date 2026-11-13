import type { CloudTrailLogQuery, LogEntry } from "@p0security/connector-core";

import { matchesAnyGlob } from "../patterns.ts";
import { sessionArnSource } from "./query.ts";
import { eventActions } from "./services.ts";

/** The fields of a CloudTrail event the connector reads. */
export type CloudTrailEvent = {
  eventID?: string;
  eventTime?: string;
  eventSource?: string;
  eventName?: string;
  recipientAccountId?: string;
  errorCode?: string;
  userIdentity?: {
    type?: string;
    arn?: string;
    principalId?: string;
    sessionContext?: { sourceIdentity?: string; [field: string]: unknown };
    [field: string]: unknown;
  };
  requestParameters?: Record<string, unknown> | null;
  resources?: { ARN?: string; type?: string; [field: string]: unknown }[];
  [field: string]: unknown;
};

/** Parses one Logs Insights `@message`, or undefined when it isn't a CloudTrail event. */
export const parseEvent = (message: string): CloudTrailEvent | undefined => {
  try {
    const event = JSON.parse(message) as unknown;
    if (
      typeof event === "object" &&
      event !== null &&
      typeof (event as CloudTrailEvent).eventID === "string" &&
      typeof (event as CloudTrailEvent).eventTime === "string"
    ) {
      return event as CloudTrailEvent;
    }
  } catch {
    // Not JSON: not a CloudTrail event.
  }
  return undefined;
};

const DENIED_ERROR_CODES =
  /AccessDenied|UnauthorizedOperation|Unauthorized|Forbidden|AuthFailure/i;

/** The partition of the caller's ARN (`aws`, `aws-us-gov`, `aws-cn`), so a
 * derived ARN lives in the same partition as the call. */
const partitionOf = (event: CloudTrailEvent) =>
  /^arn:([^:]+):/.exec(event.userIdentity?.arn ?? "")?.[1] ?? "aws";

/**
 * The ARNs an event acts on: its `resources`, or for S3 calls without them
 * (most management events), the bucket and object from its request.
 */
export const resourceArns = (event: CloudTrailEvent) => {
  const arns = (event.resources ?? [])
    .map((r) => r.ARN)
    .filter((arn): arn is string => typeof arn === "string" && arn !== "");
  if (arns.length > 0) return arns;
  const params = event.requestParameters ?? {};
  if (
    event.eventSource === "s3.amazonaws.com" &&
    typeof params.bucketName === "string"
  ) {
    const bucket = `arn:${partitionOf(event)}:s3:::${params.bucketName}`;
    return typeof params.key === "string"
      ? [`${bucket}/${params.key}`, bucket]
      : [bucket];
  }
  return [];
};

/** The resource to show: an object ARN over its bucket, else the first. */
const primaryResource = (event: CloudTrailEvent, arns: string[]) =>
  event.resources?.find((r) => r.type?.endsWith("::Object") && r.ARN)?.ARN ??
  arns[0];

export const toLogEntry = (event: CloudTrailEvent): LogEntry => {
  const { action } = eventActions(
    event.eventSource ?? "unknown",
    event.eventName ?? "unknown"
  );
  const arns = resourceArns(event);
  const resource = primaryResource(event, arns);
  return {
    id: event.eventID!,
    time: new Date(event.eventTime!).toISOString(),
    action,
    ...(resource ? { resource } : {}),
    result:
      event.errorCode && DENIED_ERROR_CODES.test(event.errorCode)
        ? "denied"
        : "allowed",
    principal:
      event.userIdentity?.arn ?? event.userIdentity?.principalId ?? "unknown",
    raw: event,
  };
};

/** An S3 object ARN: `arn:<partition>:s3:::<bucket>/<key>`. */
const isS3ObjectArn = (arn: string) => /^arn:[^:]+:s3:::[^/]+\/./.test(arn);

/**
 * The ARNs a grant's resource patterns are checked against. An S3 object
 * call names its bucket too, and a bucket-level grant (`s3:ListBucket` on
 * the bucket) must not admit reads of objects outside the grant's object
 * patterns, so only the object counts when there is one.
 */
const narrowingArns = (event: CloudTrailEvent) => {
  const arns = resourceArns(event);
  const objects = arns.filter(isS3ObjectArn);
  return objects.length > 0 ? objects : arns;
};

const identityMatches = (query: CloudTrailLogQuery, event: CloudTrailEvent) => {
  const { identity } = query;
  const arn = event.userIdentity?.arn ?? "";
  const arnSource = sessionArnSource(query.accountId, identity);
  if (arnSource !== undefined && !new RegExp(arnSource, "i").test(arn)) {
    return false;
  }
  switch (identity.kind) {
    case "assumed-role":
      return true;
    case "source-identity":
      return (
        event.userIdentity?.sessionContext?.sourceIdentity === identity.value
      );
    case "iam-user":
      return arn === identity.userArn;
  }
};

/**
 * Whether an event belongs to the query, checked in full here whatever the
 * Logs Insights query already filtered: account, identity, time, and the
 * action and resource patterns. An event with no resource ARN to check
 * passes the resource patterns, since nothing shows it's outside them.
 */
export const eventMatches = (
  query: CloudTrailLogQuery,
  event: CloudTrailEvent,
  window: { start: number; end: number }
) => {
  if (event.recipientAccountId !== query.accountId) return false;
  const time = Date.parse(event.eventTime ?? "");
  if (!(time >= window.start && time < window.end)) return false;
  if (!identityMatches(query, event)) return false;
  if (query.actions) {
    const { authorizedBy } = eventActions(
      event.eventSource ?? "",
      event.eventName ?? ""
    );
    // IAM action names are case-insensitive.
    if (!authorizedBy.some((a) => matchesAnyGlob(a, query.actions!, "i"))) {
      return false;
    }
  }
  if (query.resources) {
    const arns = narrowingArns(event);
    if (
      arns.length > 0 &&
      !arns.some((arn) => matchesAnyGlob(arn, query.resources!))
    ) {
      return false;
    }
  }
  return true;
};
