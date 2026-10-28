import {
  ConnectorError,
  type ConnectorErrorType,
  connectorErrorTypeForHttpStatus,
  throwAssertNever,
} from "@p0security/connector-core";

import { QUERY_HOST, QUERY_TIMEOUT } from "../query/client.ts";
import { type Api, CLOUD_HOST, CLOUD_TIMEOUT, ClickHouseError } from "./api.ts";

/** Where a ClickHouse Cloud call was aimed, for the messages a failure turns into. */
export type CloudTarget = {
  organizationId: string;
  /** What the call was about, such as `service prod` or `role p0_ab12_alice`. */
  subject?: string;
};

type AnsweredError = ClickHouseError & { status: number };

// Every reading of a ClickHouse Cloud status is here, so no caller compares one.
const answered = (error: unknown, statuses: number[]): error is AnsweredError =>
  error instanceof ClickHouseError &&
  error.status !== undefined &&
  statuses.includes(error.status);

/** 401: ClickHouse Cloud doesn't take the key: a wrong ID or secret, or a disabled or expired key. */
export const isKeyRejected = (error: unknown): error is AnsweredError =>
  answered(error, [401]);

/** 403: the key is taken, but lacks a permission the call needs. */
export const isForbidden = (error: unknown): error is AnsweredError =>
  answered(error, [403]);

/** 404: what the call was about isn't there (any more). */
export const isNotFound = (error: unknown): error is AnsweredError =>
  answered(error, [404]);

/**
 * 400, 403 or 404 from `GET /v1/organizations/{id}`: the key isn't one of
 * this organization's, or lacks `control-plane:organization:view`. The
 * OpenAPI documents only 400 for the call, so all three are taken.
 */
export const isOtherOrganization = (error: unknown): error is AnsweredError =>
  answered(error, [400, 403, 404]);

/**
 * 400 or 404 from `PATCH` or `DELETE …/roles/{roleId}`: the role may be gone.
 * The OpenAPI documents only 400 for those calls, so both are taken, and the
 * caller lists the roles again to find out.
 */
export const isRoleWriteRefused = (error: unknown): error is AnsweredError =>
  answered(error, [400, 404]);

/** 400 or 409: ClickHouse Cloud won't do what the request asks, and says why. */
export const isInvalidRequest = (error: unknown): error is AnsweredError =>
  answered(error, [400, 409]);

/** 429: ClickHouse Cloud is rate limiting the key. */
export const isTooManyRequests = (error: unknown): error is AnsweredError =>
  answered(error, [429]);

// How long to wait after a 429 that doesn't say, in milliseconds: one
// 10-second rate-limit window.
const DEFAULT_RETRY_AFTER = 10_000;

/**
 * How long a 429's `Retry-After` says to wait, in milliseconds: a number of
 * seconds or an HTTP date. One window when it's absent or unreadable.
 */
export const retryDelay = (retryAfter: string | undefined): number => {
  const text = retryAfter?.trim() ?? "";
  if (/^\d+$/.test(text)) return Number(text) * 1000;
  const date = Date.parse(text);
  return Number.isNaN(date)
    ? DEFAULT_RETRY_AFTER
    : Math.max(0, date - Date.now());
};

/** When to retry after a 429, in words: the wait in whole seconds, at least one. */
const retryIn = (retryAfter: string | undefined): string => {
  if (retryAfter === undefined) return "a few minutes";
  const seconds = Math.max(1, Math.ceil(retryDelay(retryAfter) / 1000));
  return seconds === 1 ? "1 second" : `${seconds} seconds`;
};

/** ClickHouse Cloud's reason, or the status when it gave none, without a closing full stop. */
const reasonOf = (error: ClickHouseError): string =>
  error.messages.length > 0
    ? error.messages.join("; ").replace(/\.$/, "")
    : `HTTP ${error.status ?? "error"}`;

const typeFor = (error: ClickHouseError): ConnectorErrorType => {
  if (error.status === undefined) return "upstream_unavailable";
  if (isInvalidRequest(error)) return "validation_error";
  return connectorErrorTypeForHttpStatus(error.status);
};

const privilegesMessage = (
  error: ClickHouseError,
  { subject }: CloudTarget
): string => {
  // The Query API before the 401: the Cloud API took the same key moments
  // before, so a 401 there most likely means the reader role is missing.
  if (error.api === "query") {
    return `ClickHouse Cloud refused to run P0's Query API endpoint${
      subject === undefined ? "" : ` on ${subject}`
    } (${error.status}): ${reasonOf(error)}. Check that P0's API key has the Basic Service API Reader role, then try again.`;
  }
  if (error.status === 401) {
    return "ClickHouse Cloud rejected P0's API key (401): the key ID or secret is wrong, or the key is disabled or expired. Check the key in its secret.";
  }
  return `ClickHouse Cloud refused P0's request${
    subject === undefined ? "" : ` about ${subject}`
  } (${error.status}): ${reasonOf(error)}. Check that P0's API key has the p0-connector role with every permission P0 needs.`;
};

/**
 * A call that got no answer: a timeout or a dropped connection, which the
 * error doesn't tell apart. On the Query API the likely cause is a service
 * that's starting, so a retry soon may work.
 */
const noAnswerMessage = (api: Api): string =>
  api === "cloud"
    ? `ClickHouse Cloud's API didn't answer within ${CLOUD_TIMEOUT / 1000} seconds, or the connection dropped. Retry in a few minutes. If it keeps failing, check that the connector can reach ${CLOUD_HOST}.`
    : `ClickHouse Cloud's Query API didn't answer within ${QUERY_TIMEOUT / 1000} seconds, or the connection dropped. The service may be starting: retry in a minute. If it keeps failing, check that the connector can reach ${QUERY_HOST}.`;

/**
 * The message P0 shows for a ClickHouse Cloud failure. It never quotes
 * {@link ClickHouseError}'s own message, whose path is the connector's
 * business. Only a refusal quotes ClickHouse Cloud's reason.
 */
const messageFor = (
  type: ConnectorErrorType,
  error: ClickHouseError,
  target: CloudTarget
): string => {
  const { organizationId, subject } = target;
  switch (type) {
    case "insufficient_privileges":
      return privilegesMessage(error, target);
    case "object_not_found":
      return `ClickHouse Cloud couldn't find ${subject ?? "what P0 asked for"} in the organization ${organizationId}. Check that it still exists.`;
    case "rate_limited":
      return `ClickHouse Cloud rate-limited P0's API key. Retry in ${retryIn(
        error.retryAfter
      )}. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit.`;
    case "upstream_unavailable":
      return error.status === undefined
        ? noAnswerMessage(error.api)
        : "ClickHouse Cloud couldn't answer P0's request right now. Retry in a few minutes, and check status.clickhouse.com if it keeps failing.";
    case "already_exists":
    case "dependency_violation":
    case "unknown":
    case "validation_error":
      return `ClickHouse Cloud refused P0's request${
        subject === undefined ? "" : ` about ${subject}`
      }${error.status === undefined ? "" : ` (${error.status})`}: ${reasonOf(error)}`;
    default:
      throw throwAssertNever(type);
  }
};

/**
 * Maps a failed ClickHouse Cloud call onto the {@link ConnectorError} P0
 * surfaces. Anything that isn't a ClickHouse Cloud failure is returned as is,
 * so a bug stays a bug. A 429 that reaches this has outlasted the Cloud
 * client's retries, and goes back to P0 with `retryAfter`.
 *
 * | ClickHouse Cloud    | Type                      |
 * | ------------------- | ------------------------- |
 * | 401 or 403          | `insufficient_privileges` |
 * | 404                 | `object_not_found`        |
 * | 429                 | `rate_limited`            |
 * | 5xx, or no answer   | `upstream_unavailable`    |
 * | 400 or 409          | `validation_error`        |
 * | any other status    | `unknown`                 |
 */
export const toConnectorError = (
  error: unknown,
  target: CloudTarget
): unknown => {
  const { organizationId, subject } = target;
  if (error instanceof ConnectorError) return error;

  if (error instanceof ClickHouseError) {
    const type = typeFor(error);
    return new ConnectorError({
      type,
      message: messageFor(type, error, target),
      payload: {
        organizationId,
        api: error.api,
        // `query` is the field P0 reads off an `object_not_found`.
        ...(type === "object_not_found"
          ? { query: subject ?? organizationId }
          : {}),
        ...(error.status !== undefined ? { status: error.status } : {}),
        ...(error.retryAfter !== undefined
          ? { retryAfter: error.retryAfter }
          : {}),
      },
    });
  }

  return error;
};

/** Runs ClickHouse Cloud calls, mapping any failure through {@link toConnectorError}. */
export const callCloud = async <T>(
  fn: () => Promise<T>,
  target: CloudTarget
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw toConnectorError(error, target);
  }
};
