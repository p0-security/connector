import { randomUUID } from "node:crypto";
import { vi } from "vitest";
import { z } from "zod";

import { setPacing } from "../cloud/client.ts";
import { REQUIRED_PERMISSIONS } from "../cloud/permissions.ts";
import {
  P0_ENDPOINTS,
  P0_ENDPOINT_NAMES,
  endpointRequest as p0EndpointRequest,
} from "../query/endpoints.ts";
import {
  KEY_ID,
  KEY_SECRET,
  KEY_UUID,
  ORGANIZATION_ID,
  ORGANIZATION_NAME,
  SERVICE_ID,
} from "./fixtures.ts";

/**
 * One ClickHouse Cloud organization behind `fetch`: the Cloud API calls the
 * connector makes, at `api.clickhouse.cloud`, and the Query API endpoints it
 * runs, at `queries.clickhouse.cloud`, answering in the shapes the Cloud
 * OpenAPI document gives, over state a test can read and change.
 */

const CLOUD_HOST = "api.clickhouse.cloud";
const QUERY_HOST = "queries.clickhouse.cloud";

/** A request the connector sent, as ClickHouse Cloud would see it. */
export type CloudCall = {
  method: string;
  url: string;
  host: string;
  /** The path as sent. */
  path: string;
  query: Record<string, string>;
  /** Lowercased names, as `Headers` gives them. */
  headers: Record<string, string>;
  /** The body as sent, and parsed. */
  rawBody: string | undefined;
  body: unknown;
  redirect: string | undefined;
};

export type CloudReply =
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { throws: unknown };

const REQUEST_ID = "9e8d7c6b-5a49-4382-9716-05f4e3d2c1b0";

const REASONS: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
  429: "Too Many Requests",
  500: "Internal Server Error",
  503: "Service Unavailable",
};

/** The Cloud API failing a call, with its documented error body. */
export const failing = (
  status: number,
  error = REASONS[status] ?? "error",
  headers?: Record<string, string>
): CloudReply => ({
  status,
  body: { status, error, requestId: REQUEST_ID },
  headers,
});

const ok = (result: unknown, status = 200): CloudReply => ({
  status,
  body: { status, requestId: REQUEST_ID, result },
});

export type FakeService = {
  id: string;
  name: string;
  state: string;
  clickhouseVersion?: string;
  byocId?: string;
};

export type FakeEndpoint = {
  id: string;
  name: string;
  sql: string;
  database: string;
  parameters: Record<string, string>;
  apiKeyIds: string[];
  roles: string[];
  allowedOrigins: string[];
  url: string;
};

export type FakeMember = { userId: string; email: string; name: string };

/** An API key in the organization, as `GET …/keys` lists it. */
export type FakeKey = { id: string; name: string; keySuffix: string };

export type FakePolicy = {
  allowDeny: "ALLOW" | "DENY";
  permissions: string[];
  resources: string[];
  tags?: { grants?: string[]; roleV2?: string };
};

export type FakeRole = {
  id: string;
  name: string;
  type: "custom" | "system";
  actors: string[];
  policies: FakePolicy[];
};

/** The run URL ClickHouse Cloud gives an endpoint. */
export const runUrl = (id: string) => `https://${QUERY_HOST}/run/${id}`;

/** An endpoint in the fake, with whatever a test overrides. */
export const fakeEndpoint = (
  overrides: Partial<FakeEndpoint> & { name: string }
): FakeEndpoint => {
  const id = overrides.id ?? randomUUID();
  return {
    id,
    sql: "SELECT 1",
    database: "system",
    parameters: {},
    apiKeyIds: [],
    roles: ["sql_console_read_only"],
    allowedOrigins: [],
    url: runUrl(id),
    ...overrides,
  };
};

// `PublicQueryApiEndpointRequest`. The OpenAPI types `apiKeyIds` as UUIDs.
// Whether the Basic auth key ID is that UUID is INT-669's to check.
export const endpointRequest = z.strictObject({
  name: z.string().min(1),
  sql: z.string().max(4194304),
  database: z.string(),
  parameters: z.record(z.string(), z.string()).default({}),
  apiKeyIds: z.array(z.uuid()).min(1),
  roles: z.array(z.string().min(1)).min(1),
  allowedOrigins: z.array(z.string()).default([]),
});

const policyRequest = z.strictObject({
  allowDeny: z.enum(["ALLOW", "DENY"]),
  permissions: z.array(z.string()),
  resources: z.array(z.string()),
  tags: z
    .strictObject({
      grants: z.array(z.string()).optional(),
      roleV2: z.enum(["sql-console-readonly", "sql-console-admin"]).optional(),
    })
    .optional(),
});

const roleCreate = z.strictObject({
  name: z.string(),
  actors: z.array(z.string()),
  policies: z.array(policyRequest),
});

const roleUpdate = z.strictObject({
  name: z.string().optional(),
  actors: z.array(z.string()).optional(),
  policies: z.array(policyRequest).optional(),
});

const runBody = z.strictObject({
  format: z.string(),
  queryVariables: z.record(z.string(), z.unknown()).optional(),
});

type Options = {
  organizationId: string;
  organizationName: string;
  keyId: string;
  /** The key secret ClickHouse Cloud accepts. Any other is refused. */
  keySecret: string;
  /** The key's UUID, which endpoints' `apiKeyIds` hold. */
  keyUuid: string;
  /** The permissions the key's roles give. */
  permissions?: readonly string[];
  /** The most endpoints a listing page holds, at most the API's 100. */
  pageSize?: number;
};

const listItem = ({
  sql: _sql,
  parameters: _parameters,
  ...item
}: FakeEndpoint) => item;

export const newFakeCloud = (options: Options) => {
  const { organizationId, organizationName, keyId, keySecret, keyUuid } =
    options;
  // The fake has no rate limit, so the connector doesn't pace its calls or
  // retry a 429 against it. A test of the rate limit turns pacing back on.
  setPacing(false);
  const pageSize = options.pageSize ?? 100;
  const calls: CloudCall[] = [];
  const state = {
    permissions: new Set<string>(options.permissions ?? REQUIRED_PERMISSIONS),
  };
  const members: FakeMember[] = [];
  const services: FakeService[] = [];
  const endpoints = new Map<string, FakeEndpoint[]>();
  const roles: FakeRole[] = [];
  // The connector's own key, whose suffix is its key ID's, and another one.
  const keys: FakeKey[] = [
    { id: keyUuid, name: "p0-connector", keySuffix: keyId.slice(-4) },
    { id: randomUUID(), name: "terraform", keySuffix: "zz99" },
  ];
  /** What each endpoint's run returns, by its name: `[]` unless set. */
  const rows = new Map<string, unknown[]>();
  let interceptor: ((call: CloudCall) => CloudReply | undefined) | undefined;

  const credentials = Buffer.from(`${keyId}:${keySecret}`).toString("base64");
  const authorized = (call: CloudCall) =>
    call.headers.authorization === `Basic ${credentials}`;

  const endpointsOf = (serviceId: string): FakeEndpoint[] => {
    const held = endpoints.get(serviceId) ?? [];
    endpoints.set(serviceId, held);
    return held;
  };

  const requires = (permission: string): CloudReply | undefined =>
    state.permissions.has(permission)
      ? undefined
      : failing(403, `The API key lacks ${permission}`);

  const endpointApi = (
    call: CloudCall,
    serviceId: string,
    endpointId: string | undefined
  ): CloudReply => {
    const held = endpointsOf(serviceId);
    const view = "control-plane:service:view-query-api-endpoints";
    const manage = "control-plane:service:manage-query-api-endpoints";
    if (endpointId === undefined) {
      if (call.method === "GET") {
        const denied = requires(view);
        if (denied) return denied;
        const limit = Math.min(Number(call.query.limit ?? "100"), pageSize);
        const start = Number(call.query.cursor ?? "0");
        const page = held.slice(start, start + limit);
        const next = start + limit < held.length ? String(start + limit) : null;
        return {
          status: 200,
          body: {
            result: page.map(listItem),
            limit,
            totalCount: held.length,
            nextCursor: next,
            status: 200,
            requestId: REQUEST_ID,
          },
        };
      }
      if (call.method === "POST") {
        const denied = requires(manage);
        if (denied) return denied;
        const parsed = endpointRequest.safeParse(call.body);
        if (!parsed.success) return failing(400, "Invalid request body");
        const created = fakeEndpoint(parsed.data);
        held.push(created);
        return ok(created, 201);
      }
      return failing(404);
    }
    const index = held.findIndex(({ id }) => id === endpointId);
    const found = held[index];
    if (found === undefined) return failing(404, "Endpoint not found");
    if (call.method === "GET") {
      return requires(view) ?? ok(found);
    }
    const denied = requires(manage);
    if (denied) return denied;
    if (call.method === "PUT") {
      const parsed = endpointRequest.safeParse(call.body);
      if (!parsed.success) return failing(400, "Invalid request body");
      const updated = { ...found, ...parsed.data };
      held[index] = updated;
      return ok(updated);
    }
    if (call.method === "DELETE") {
      held.splice(index, 1);
      return { status: 200, body: { status: 200, requestId: REQUEST_ID } };
    }
    return failing(404);
  };

  const roleApi = (call: CloudCall, roleId: string | undefined): CloudReply => {
    const denied = requires("control-plane:organization:manage");
    if (denied) return denied;
    if (roleId === undefined) {
      if (call.method === "GET") return ok(roles);
      if (call.method === "POST") {
        const parsed = roleCreate.safeParse(call.body);
        if (!parsed.success) return failing(400, "Invalid request body");
        const created: FakeRole = {
          id: randomUUID(),
          type: "custom",
          ...parsed.data,
        };
        roles.push(created);
        return ok(created);
      }
      return failing(404);
    }
    const index = roles.findIndex(({ id }) => id === roleId);
    const found = roles[index];
    if (found === undefined) return failing(400, "Role not found");
    if (call.method === "PATCH") {
      const parsed = roleUpdate.safeParse(call.body);
      if (!parsed.success) return failing(400, "Invalid request body");
      const updated = { ...found, ...parsed.data };
      roles[index] = updated;
      return ok(updated);
    }
    if (call.method === "DELETE") {
      roles.splice(index, 1);
      return { status: 200, body: { status: 200, requestId: REQUEST_ID } };
    }
    return failing(404);
  };

  const cloudApi = (call: CloudCall): CloudReply => {
    if (!authorized(call)) return failing(401, "Invalid credentials");
    const [version, organizations, org, ...rest] = call.path
      .split("/")
      .filter(Boolean);
    if (version !== "v1" || organizations !== "organizations") {
      return failing(404);
    }
    if (org !== organizationId) return failing(403, "Forbidden");
    const [collection, id, sub, subId, ...extra] = rest;
    if (extra.length > 0) return failing(404);
    if (collection === undefined && call.method === "GET") {
      return (
        requires("control-plane:organization:view") ??
        ok({
          id: organizationId,
          name: organizationName,
          createdAt: "2026-01-01T00:00:00Z",
        })
      );
    }
    if (collection === "keys" && id === undefined && call.method === "GET") {
      const denied = requires("control-plane:organization:view-api-keys");
      if (denied) return denied;
      const start = Number(call.query.cursor ?? "0");
      const listed = keys.slice(start, start + pageSize);
      const next =
        start + pageSize < keys.length ? String(start + pageSize) : null;
      return {
        status: 200,
        body: {
          status: 200,
          requestId: REQUEST_ID,
          result: listed.map((key) => ({ ...key, state: "enabled" })),
          limit: pageSize,
          totalCount: keys.length,
          nextCursor: next,
        },
      };
    }
    if (collection === "members" && id === undefined && call.method === "GET") {
      return requires("control-plane:organization:view") ?? ok(members);
    }
    if (collection === "roles" && sub === undefined) {
      return roleApi(call, id);
    }
    if (collection === "services") {
      if (id === undefined) {
        // Listing the services needs no permission beyond a valid key.
        return call.method === "GET" ? ok(services) : failing(404);
      }
      const service = services.find((s) => s.id === id);
      if (service === undefined) return failing(404, "Service not found");
      if (sub === undefined && call.method === "GET") {
        return requires("control-plane:service:view") ?? ok(service);
      }
      if (sub === "query-api-endpoints") return endpointApi(call, id, subId);
    }
    return failing(404);
  };

  const queryApi = (call: CloudCall): CloudReply => {
    if (!authorized(call)) return { status: 401, body: "Unauthorized" };
    const [run, id, ...extra] = call.path.split("/").filter(Boolean);
    if (call.method !== "POST" || run !== "run" || extra.length > 0) {
      return { status: 404, body: "Not Found" };
    }
    const found = [...endpoints.values()]
      .flat()
      .find((endpoint) => endpoint.id === id);
    if (found === undefined) return { status: 404, body: "Endpoint not found" };
    if (call.headers["x-clickhouse-endpoint-version"] !== "2") {
      return { status: 400, body: "Unsupported endpoint version" };
    }
    const body = runBody.safeParse(call.body);
    if (!body.success || body.data.format !== "JSONEachRow") {
      return { status: 400, body: "Invalid request body" };
    }
    if (!found.apiKeyIds.includes(keyUuid)) {
      return { status: 403, body: "The API key can't run this endpoint" };
    }
    const answer = rows.get(found.name) ?? [];
    return {
      status: 200,
      body: answer.map((row) => `${JSON.stringify(row)}\n`).join(""),
      headers: { "content-type": "application/x-ndjson" },
    };
  };

  const answer = (call: CloudCall): CloudReply => {
    if (call.host === CLOUD_HOST) return cloudApi(call);
    if (call.host === QUERY_HOST) return queryApi(call);
    return { throws: new TypeError("fetch failed") };
  };

  const fetch = vi.fn<typeof globalThis.fetch>(async (resource, init) => {
    const url = new URL(
      resource instanceof Request ? resource.url : resource.toString()
    );
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    const call: CloudCall = {
      method: init?.method ?? "GET",
      url: url.toString(),
      host: url.host,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers: Object.fromEntries(new Headers(init?.headers)),
      rawBody,
      body: rawBody === undefined ? undefined : JSON.parse(rawBody),
      redirect: init?.redirect,
    };
    calls.push(call);
    const reply = interceptor?.(call) ?? answer(call);
    if ("throws" in reply) throw reply.throws;
    const { status, body, headers } = reply;
    return new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers }
    );
  });

  const isRun = ({ host }: CloudCall) => host === QUERY_HOST;

  return {
    /** Stub the global `fetch` with this, and no real network call is made. */
    fetch,
    /** The key's permissions, to read or to change. */
    state,
    /** The organization's members, services, roles and each service's endpoints, to read or to change. */
    members,
    services,
    roles,
    keys,
    endpointsOf,
    /** What a run of each endpoint returns, by its name. */
    rows,
    /** Every request sent, in order. */
    calls,
    /** Answers a call some other way, whenever `reply` returns an answer. */
    intercept: (reply: (call: CloudCall) => CloudReply | undefined) => {
      interceptor = reply;
    },
    /** The endpoint runs sent. */
    runs: () => calls.filter(isRun),
    /** What was asked to change: every Cloud API request but a `GET`. */
    writes: () =>
      calls
        .filter((call) => call.method !== "GET" && !isRun(call))
        .map(({ method, path, body }) => ({ method, path, body })),
  };
};

export type FakeCloud = ReturnType<typeof newFakeCloud>;

/** Matches a call by its method and its path, for {@link FakeCloud.intercept}. */
export const isCall =
  (method: string, path: RegExp | string) =>
  (call: CloudCall): boolean =>
    call.method === method &&
    (typeof path === "string" ? call.path === path : path.test(call.path));

/**
 * The fake with the fixtures' organization and key, and one running
 * service on ClickHouse 26.4, which no P0 endpoint is on yet.
 */
export const newSeededCloud = (
  options: Partial<Options> & { service?: Partial<FakeService> } = {}
) => {
  const { service, ...rest } = options;
  const cloud = newFakeCloud({
    organizationId: ORGANIZATION_ID,
    organizationName: ORGANIZATION_NAME,
    keyId: KEY_ID,
    keySecret: KEY_SECRET,
    keyUuid: KEY_UUID,
    ...rest,
  });
  cloud.services.push({
    id: SERVICE_ID,
    name: "prod",
    state: "running",
    clickhouseVersion: "26.4.1.1234",
    ...service,
  });
  return cloud;
};

/**
 * P0's endpoints on a service, exactly as the install leaves them for the
 * fixtures' key. Returns them by name.
 */
export const provisionP0Endpoints = (
  cloud: FakeCloud,
  serviceId: string = SERVICE_ID
): Record<string, FakeEndpoint> => {
  const held = cloud.endpointsOf(serviceId);
  return Object.fromEntries(
    P0_ENDPOINT_NAMES.map((name) => {
      const endpoint = fakeEndpoint(
        p0EndpointRequest(P0_ENDPOINTS[name], KEY_UUID)
      );
      held.push(endpoint);
      return [name, endpoint];
    })
  );
};
