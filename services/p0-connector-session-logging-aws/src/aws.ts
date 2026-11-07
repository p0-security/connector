import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";

/**
 * The AWS calls the connector makes, behind `send` so tests answer them from
 * recorded responses without a network. Both clients use the Lambda's own
 * region and execution role.
 */
export type AwsDependencies = {
  logs?: Pick<CloudWatchLogsClient, "send">;
  cloudtrail?: Pick<CloudTrailClient, "send">;
  /** The current time, in epoch milliseconds. */
  now?: () => number;
  /** Waits between polls of a running Logs Insights query. */
  wait?: (ms: number) => Promise<void>;
};

export type Aws = Required<AwsDependencies>;

export const newAws = (dependencies: AwsDependencies = {}): Aws => ({
  logs: dependencies.logs ?? new CloudWatchLogsClient({}),
  cloudtrail: dependencies.cloudtrail ?? new CloudTrailClient({}),
  now: dependencies.now ?? Date.now,
  wait:
    dependencies.wait ??
    ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
});

const SDK_ERROR_TYPES: Record<string, ConnectorErrorOptions["type"]> = {
  AccessDeniedException: "insufficient_privileges",
  UnauthorizedOperation: "insufficient_privileges",
  ResourceNotFoundException: "object_not_found",
  TrailNotFoundException: "object_not_found",
  InvalidParameterException: "validation_error",
  MalformedQueryException: "validation_error",
  LimitExceededException: "rate_limited",
  ThrottlingException: "rate_limited",
  ServiceUnavailableException: "upstream_unavailable",
};

/** Maps an AWS SDK failure to the error P0 shows. AWS's message names
 * resources but never holds a credential. */
export const toConnectorError = (error: unknown): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const { name, message } = (error ?? {}) as {
    name?: string;
    message?: string;
  };
  return new ConnectorError({
    type: (name && SDK_ERROR_TYPES[name]) || "unknown",
    message: message ?? "The AWS call failed",
    payload: name ? { awsError: name } : {},
    cause: error,
  });
};

export const isNotFound = (error: unknown) =>
  (error as { name?: string } | undefined)?.name ===
  "ResourceNotFoundException";
