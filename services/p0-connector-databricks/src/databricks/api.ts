import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";
import { z } from "zod";

import databricksConnectorPackageJson from "../../package.json" with { type: "json" };

const logger = createLogger();

/** How long any one call the connector makes, to Databricks or to AWS STS, may take. */
export const API_TIMEOUT_MS = 10_000;

export const CONNECTOR_VERSION =
  databricksConnectorPackageJson.version ?? "unknown";

/**
 * The `User-Agent` on every call to Databricks. Databricks records it in its
 * audit system table, where the actor is the connector's principal, so a
 * customer can join a Databricks audit event to the P0 request that caused it.
 */
const userAgent = (requestId: string) =>
  `p0-connector-databricks/${CONNECTOR_VERSION} request/${requestId}`;

export type DatabricksRequest = {
  /** An origin already validated by the `accountsUrl` or `workspaceUrl` parser. */
  origin: string;
  method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT";
  path: string;
  requestId: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
};

/**
 * Databricks' own error text in a REST (`message`), SCIM (`detail`) or OAuth
 * (`error_description`) error body, and its error code (`error_code`, or
 * OAuth's `error`). Anything else in the body is ignored.
 */
const errorBody = z
  .object({
    message: z.string().optional().catch(undefined),
    detail: z.string().optional().catch(undefined),
    error_description: z.string().optional().catch(undefined),
    error_code: z.string().optional().catch(undefined),
    error: z.string().optional().catch(undefined),
  })
  .transform((body) => ({
    message: body.message ?? body.detail ?? body.error_description,
    errorCode: body.error_code ?? body.error,
  }));

const errorDetails = (
  data: unknown
): { message?: string; errorCode?: string } => {
  const parsed = errorBody.safeParse(data);
  return parsed.success ? parsed.data : {};
};

/**
 * Makes one HTTP call to Databricks and returns the parsed JSON body (or
 * `undefined` for an empty one). The body is `unknown`: every caller parses it
 * with its own schema, through {@link parse}.
 *
 * Any failure becomes a {@link ConnectorError} built from the status and
 * Databricks' own error text only. The request is never attached to the error
 * or the log, because its headers or body carry a bearer token or the AWS web
 * identity token.
 */
export const databricksRequest = async (
  request: DatabricksRequest
): Promise<unknown> => {
  const { origin, method, path, requestId, query, headers, body } = request;
  const url = `${origin}${path}${
    query ? `?${new URLSearchParams(query).toString()}` : ""
  }`;
  const logFields = { method, origin, path, requestId };

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: { ...headers, "User-Agent": userAgent(requestId) },
      body,
      // Only `origin` was checked, so a redirect is never followed: a 307 or
      // 308 would resend the body, such as the token exchange's AWS identity
      // token, to whatever host its `Location` names. A redirect fails here.
      redirect: "error",
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch (error) {
    logger.error({ ...logFields, error }, "Databricks request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Databricks ${method} ${path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: { requestId },
    });
  }

  let text: string;
  try {
    text = await response.text();
  } catch (error) {
    // The timeout firing mid-body, or a reset socket. On an error response
    // the status already says what happened, so the status text stands in.
    // On a 2xx the change may or may not have happened, so it must not read
    // as an unexpected (but complete) response.
    if (response.ok) {
      logger.error(
        { ...logFields, status: response.status, error },
        "Databricks response body could not be read"
      );
      throw new ConnectorError({
        type: "upstream_unavailable",
        message: `Databricks ${method} ${path} returned ${response.status}, but its response could not be read`,
        payload: { requestId, status: response.status },
      });
    }
    text = "";
  }
  const data: unknown = text ? safeJsonParse(text) : undefined;

  if (!response.ok) {
    const { status } = response;
    const { message, errorCode } = errorDetails(data);
    // Callers expect some of these, such as a 404 for a user or securable
    // that's gone. Every route logs the failures that reach it.
    logger.debug(
      { ...logFields, status, errorCode, message },
      "Databricks request returned a non-2xx response"
    );
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `Databricks ${method} ${path} failed (${status}): ${
        message ?? response.statusText
      }`,
      payload: {
        requestId,
        status,
        ...(errorCode ? { errorCode } : {}),
      },
    });
  }

  if (text && data === undefined) {
    logger.warn(
      { ...logFields, status: response.status, length: text.length },
      "Databricks returned a 2xx response that isn't JSON"
    );
  }

  logger.debug(
    { ...logFields, status: response.status },
    "Databricks request succeeded"
  );
  return data;
};

const safeJsonParse = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/**
 * Parses a Databricks response with `schema`. A response that doesn't match
 * is logged with the schema's issues and fails as `unknown`, naming `what`.
 */
export const parse = <T>({
  schema,
  data,
  what,
  requestId,
}: {
  schema: z.ZodType<T>;
  data: unknown;
  /** The API that returned `data`, e.g. "account SCIM Users". */
  what: string;
  requestId: string;
}): T => {
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    logger.error(
      { requestId, what, issues: parsed.error.issues },
      "Databricks returned an unexpected response"
    );
    throw new ConnectorError({
      type: "unknown",
      message: `Databricks ${what} returned an unexpected response`,
      payload: { requestId },
    });
  }
  return parsed.data;
};

const failedRequestPayload = z.object({
  status: z.number(),
  errorCode: z.string().optional(),
});

/**
 * The status and Databricks error code of a call {@link databricksRequest}
 * failed with a non-2xx response, or `undefined` for any other error.
 */
export const failedRequest = (error: unknown) => {
  if (!(error instanceof ConnectorError)) return undefined;
  const parsed = failedRequestPayload.safeParse(error.data.payload);
  return parsed.success ? parsed.data : undefined;
};

/**
 * Runs `call`, throwing `refusal(error)` in place of a Databricks 403, so the
 * error says which role P0's principal lacks instead of the bare status.
 */
export const withForbiddenAs = async <T>(
  refusal: (cause: unknown) => ConnectorError,
  call: () => Promise<T>
): Promise<T> => {
  try {
    return await call();
  } catch (error) {
    if (failedRequest(error)?.status === 403) throw refusal(error);
    throw error;
  }
};

/** Whether `error` is a Databricks 404, such as a user or workspace that isn't there. */
export const isNotFound = (error: unknown) =>
  failedRequest(error)?.status === 404;

/**
 * Whether `error` is a Databricks 404 carrying one of the error codes in
 * `codes`. A 404 without one, such as a proxy's, doesn't count, so a caller
 * that reads this as "already gone" fails closed.
 */
export const isNotFoundWith = (error: unknown, codes: ReadonlySet<string>) => {
  const failed = failedRequest(error);
  return (
    failed?.status === 404 &&
    failed.errorCode !== undefined &&
    codes.has(failed.errorCode)
  );
};

/**
 * Shares one `load` per key in `cache`: concurrent callers wait on the same
 * promise, and later callers get its result. A rejection is evicted, so the
 * next call retries.
 */
export const memoizeByKey = <T>(
  cache: Map<string, Promise<T>>,
  key: string,
  load: () => Promise<T>
): Promise<T> => {
  const cached = cache.get(key);
  if (cached) return cached;
  const pending = load().catch((error: unknown) => {
    // Evict only this entry, not one a later call put there since.
    if (cache.get(key) === pending) cache.delete(key);
    throw error;
  });
  cache.set(key, pending);
  return pending;
};
