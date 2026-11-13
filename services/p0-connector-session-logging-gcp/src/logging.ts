import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";
import { GoogleAuth } from "google-auth-library";

/** The `entries.list` request body. */
export type ListEntriesRequest = {
  resourceNames: string[];
  filter: string;
  orderBy: "timestamp asc" | "timestamp desc";
  pageSize: number;
  pageToken?: string;
};

export type ListEntriesResponse = {
  entries?: Record<string, unknown>[];
  nextPageToken?: string;
};

/**
 * The Cloud Logging calls the connector makes, behind one function so tests
 * answer them from recorded entries without a network. A failure carries the
 * HTTP `status` it came back with.
 */
export type LoggingDependencies = {
  /** `signal` aborts the request when the read's budget runs out. */
  listEntries?: (
    request: ListEntriesRequest,
    signal?: AbortSignal
  ) => Promise<ListEntriesResponse>;
  /** The current time, in epoch milliseconds. */
  now?: () => number;
  /** Waits before retrying a throttled call. */
  wait?: (ms: number) => Promise<void>;
};

export type Logging = Required<LoggingDependencies>;

const ENTRIES_LIST_URL = "https://logging.googleapis.com/v2/entries:list";

const READ_SCOPE = "https://www.googleapis.com/auth/logging.read";

/** `entries.list` as the Cloud Run service's own service account. */
const newListEntries = () => {
  const auth = new GoogleAuth({ scopes: [READ_SCOPE] });
  return async (request: ListEntriesRequest, signal?: AbortSignal) => {
    const client = await auth.getClient();
    const response = await client.request<ListEntriesResponse>({
      url: ENTRIES_LIST_URL,
      method: "POST",
      data: request,
      ...(signal ? { signal } : {}),
    });
    return response.data;
  };
};

export const newLogging = (
  dependencies: LoggingDependencies = {}
): Logging => ({
  listEntries: dependencies.listEntries ?? newListEntries(),
  now: dependencies.now ?? Date.now,
  wait:
    dependencies.wait ??
    ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
});

/** The HTTP status of a failed call, from a gaxios error or a test's. */
export const statusOf = (error: unknown) => {
  const e = error as
    { status?: unknown; response?: { status?: unknown } } | undefined;
  const status = e?.response?.status ?? e?.status;
  return typeof status === "number" ? status : undefined;
};

const STATUS_TYPES: Record<number, ConnectorErrorOptions["type"]> = {
  400: "validation_error",
  401: "insufficient_privileges",
  403: "insufficient_privileges",
  404: "object_not_found",
  429: "rate_limited",
};

/** Maps a Cloud Logging failure to the error P0 shows. */
export const toConnectorError = (error: unknown): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const status = statusOf(error);
  const type =
    (status !== undefined && STATUS_TYPES[status]) ||
    (status !== undefined && status >= 500
      ? "upstream_unavailable"
      : "unknown");
  return new ConnectorError({
    type,
    message:
      (error as { message?: string } | undefined)?.message ??
      "The Cloud Logging call failed",
    payload: status !== undefined ? { status } : {},
    cause: error,
  });
};

/** A Logging filter string literal. */
export const filterString = (value: string) =>
  `"${value.replace(/["\\]/g, "\\$&")}"`;

/** A Cloud Audit Logs log name in a project. */
export const auditLogName = (projectId: string, log: string) =>
  `projects/${projectId}/logs/cloudaudit.googleapis.com%2F${log}`;

/**
 * A project ID or a domain-scoped one (`example.com:project`). Checked
 * before it goes into a resource name or a filter.
 */
export const assertProjectId = (projectId: string) => {
  if (!/^([a-z0-9.-]+:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `${projectId} isn't a GCP project ID`,
      payload: { projectId },
    });
  }
  return projectId;
};
