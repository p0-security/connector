import { ConnectorError, type Logger } from "@p0security/connector-core";
import { compact, once } from "lodash-es";
import { z } from "zod";

import type { OrganizationCredentials } from "../credentials.ts";
import { isP0Name, requireP0Role } from "../namespace.ts";
import {
  type QueryVariables,
  type Runnable,
  runEndpoint,
} from "../query/client.ts";
import { type ApiKeyValue, readApiKey } from "../secrets.ts";
import {
  type CloudRequest,
  type Method,
  cloudRequest,
  parseResponse,
  segment,
} from "./api.ts";
import { isTooManyRequests, retryDelay } from "./errors.ts";

/**
 * The Cloud API's shapes, from its OpenAPI document
 * (`https://api.clickhouse.cloud/v1`). Only the fields the connector reads
 * are parsed, and every other is dropped.
 */

const organization = z.object({ id: z.string(), name: z.string() });

export type Organization = z.infer<typeof organization>;

const member = z.object({
  userId: z.string(),
  email: z.string().optional(),
  name: z.string().optional(),
});

export type Member = z.infer<typeof member>;

const service = z.object({
  id: z.string(),
  name: z.string(),
  /** Such as `running`, `idle` or `stopped`. Kept as text, so a new state still parses. */
  state: z.string().optional(),
  clickhouseVersion: z.string().optional(),
  /** Set for a BYOC service. */
  byocId: z.string().nullish(),
});

export type Service = z.infer<typeof service>;

// `PublicQueryApiEndpointListItem`: a listing leaves out `sql` and `parameters`.
const listedEndpoint = z.object({
  id: z.string(),
  name: z.string(),
  database: z.string(),
  apiKeyIds: z.array(z.string()),
  roles: z.array(z.string()),
  allowedOrigins: z.array(z.string()),
  url: z.string(),
});

export type ListedEndpoint = z.infer<typeof listedEndpoint>;

// `PublicQueryApiEndpoint`.
const endpoint = listedEndpoint.extend({
  sql: z.string(),
  parameters: z.record(z.string(), z.string()),
});

export type Endpoint = z.infer<typeof endpoint>;

/** `PublicQueryApiEndpointRequest`, the body of a create and of an update. */
export type EndpointRequest = {
  name: string;
  sql: string;
  database: string;
  parameters: Record<string, string>;
  apiKeyIds: string[];
  roles: string[];
  allowedOrigins: string[];
};

// ClickHouse Cloud may send `null` for a field it has no value for. These
// read it as absent, or as an empty list.
const nullable = <T>(schema: z.ZodType<T>) =>
  schema.nullish().transform((value) => value ?? undefined);

const list = <T>(item: z.ZodType<T>) =>
  z
    .array(item)
    .nullish()
    .transform((items) => items ?? []);

const policyTags = z.object({
  grants: nullable(z.array(z.string())),
  roleV2: nullable(z.string()),
});

// `RBACPolicy`.
const policy = z.object({
  allowDeny: z.enum(["ALLOW", "DENY"]),
  permissions: z.array(z.string()),
  resources: z.array(z.string()),
  tags: policyTags.nullish(),
});

export type Policy = z.infer<typeof policy>;

/** `RBACPolicyCreateRequest`. */
export type PolicyRequest = {
  allowDeny: "ALLOW" | "DENY";
  permissions: string[];
  resources: string[];
  tags?: { grants?: string[]; roleV2?: string };
};

// `RBACRole`.
const role = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string().optional(),
  actors: list(z.string()),
  policies: list(policy),
});

export type Role = z.infer<typeof role>;

// Enough of a role the connector can't read to tell whose it is.
const roleHeader = z
  .object({
    id: z.string().optional().catch(undefined),
    name: z.string().optional().catch(undefined),
    type: z.string().optional().catch(undefined),
  })
  .catch({});

// `ApiKey`: the organization's keys, as `GET …/keys` lists them.
const apiKey = z.object({
  /** The key's UUID, which an endpoint's `apiKeyIds` takes. Not the Basic auth key ID. */
  id: z.string(),
  /** The OpenAPI's "last 4 letters of the key". */
  keySuffix: z.string().optional(),
});

export type ListedApiKey = z.infer<typeof apiKey>;

// Every documented 2xx body is `{ status, requestId, result }`.
const envelope = <T>(result: z.ZodType<T>): z.ZodType<{ result: T }> =>
  z.object({ result });

// A listing the OpenAPI documents in one piece, without paging. The paging
// fields the paged listings carry are read anyway, so one that pages after
// all is caught rather than read as whole.
const unpaged = <T>(item: z.ZodType<T>) =>
  z.object({
    result: z.array(item),
    nextCursor: z.string().nullish(),
    totalCount: z.number().nullish(),
  });

// A page of a listing that pages: `{ result, nextCursor }`.
const page = <T>(item: z.ZodType<T>) =>
  z.object({ result: z.array(item), nextCursor: z.string().nullish() });

// The most the endpoint listing gives on a page.
const ENDPOINT_PAGE_SIZE = 100;

// The most pages of a listing the connector reads before it gives up.
const MAX_PAGES = 100;

/**
 * Each key's UUID, by `<organizationId>/<keyId>`, for the process's lifetime:
 * a key's UUID never changes, and a new key has a new key ID. The
 * organization is part of the key, so an organization pointed at another
 * one's secret looks the key up among its own keys, and fails there.
 */
const keyUuids = new Map<string, string>();

/** Forgets every key's UUID. For tests. */
export const forgetKeyUuids = () => keyUuids.clear();

/**
 * ClickHouse Cloud allows each API key 10 requests over a 10-second window
 * (https://clickhouse.com/docs/cloud/manage/api/api-overview). The page
 * doesn't say whether runs of Query API endpoints count, so only Cloud API
 * calls are paced.
 */
const RATE_LIMIT_REQUESTS = 10;

// The 10-second window, with a second to spare: ClickHouse Cloud counts a
// request when it arrives, and the connector when it sends it.
const RATE_LIMIT_WINDOW = 11_000;

/**
 * How long into one connector call the client still waits on the rate
 * limit, in milliseconds: well under the Lambda's 300 s timeout, so a call
 * that runs out fails as `rate_limited` rather than being cut off.
 */
export const RATE_LIMIT_BUDGET = 240_000;

let pacing = true;

/**
 * Turns pacing and the 429 retry off, or back on. For tests: a fake Cloud
 * has no rate limit, and a test that isn't about it shouldn't wait.
 */
export const setPacing = (on: boolean) => {
  pacing = on;
};

const sleep = (ms: number) =>
  ms > 0
    ? new Promise<void>((resolve) => setTimeout(resolve, ms))
    : Promise.resolve();

/**
 * The turns of one connector call's Cloud API calls: at most
 * {@link RATE_LIMIT_REQUESTS} in any {@link RATE_LIMIT_WINDOW}. A call takes
 * its turn when it asks, so calls made at once queue in order.
 */
const newPacer = () => {
  const started = Date.now();
  // When each of the last few calls was, or will be, sent.
  const sent: number[] = [];
  return {
    /** How long it's been since the connector call began, in milliseconds. */
    elapsed: () => Date.now() - started,
    /** Takes the next turn, and says how long to wait for it. */
    turn: (): number => {
      const now = Date.now();
      const oldest =
        sent.length < RATE_LIMIT_REQUESTS
          ? undefined
          : sent[sent.length - RATE_LIMIT_REQUESTS];
      const at =
        oldest === undefined ? now : Math.max(now, oldest + RATE_LIMIT_WINDOW);
      sent.push(at);
      if (sent.length > RATE_LIMIT_REQUESTS) sent.shift();
      return at - now;
    },
  };
};

/**
 * The key's UUID among the organization's keys: the one whose `keySuffix` is
 * the last 4 characters of the key ID or of the key secret. The OpenAPI doesn't
 * say which of the two `keySuffix` describes. Only the count of matches is
 * ever reported: a suffix of the secret is never logged or returned.
 */
const identifyKey = (
  keys: ListedApiKey[],
  { keyId, keySecret }: { keyId: string; keySecret: string }
): string => {
  const suffixes = new Set([keyId.slice(-4), keySecret.slice(-4)]);
  const matches = keys.filter(
    ({ keySuffix }) => keySuffix !== undefined && suffixes.has(keySuffix)
  );
  const [only] = matches;
  if (only !== undefined && matches.length === 1) return only.id;
  throw new ConnectorError({
    type: "dependency_violation",
    message: `P0 couldn't tell which of the ClickHouse Cloud organization's API keys is its own: ${
      matches.length === 0 ? "none" : matches.length
    } of the organization's ${keys.length} keys end like it. Check that the key in its secret belongs to this organization.`,
    payload: { matches: matches.length, keys: keys.length },
  });
};

/** A role or endpoint to change or delete: its ID, and its name, which must be P0's. */
export type Named = { id: string; name: string };

const requireP0Endpoint = (name: string) => {
  if (!isP0Name(name)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The connector doesn't change Query API endpoints that aren't P0's, and ${name} isn't.`,
      payload: { endpoint: name },
    });
  }
};

/**
 * The organization's Cloud API, and P0's Query API endpoints on its
 * services, as the organization's API key.
 *
 * Build one per call to the connector. It reads the key once, on its first
 * call, so a rotated key or a pulled read grant takes effect on the next
 * connector call. Its Cloud API calls are paced to the key's rate limit, and
 * one that gets a 429 is sent again after `Retry-After`, until
 * {@link RATE_LIMIT_BUDGET} has passed. Failures are thrown as they are: a
 * {@link ClickHouseError} for one from ClickHouse Cloud, which the caller
 * maps with `toConnectorError`.
 */
export const newCloudClient = ({
  organizationId,
  apiKeySecret,
  log,
}: OrganizationCredentials & { log: Logger }) => {
  const readKey: () => Promise<ApiKeyValue> = once(() =>
    readApiKey(apiKeySecret)
  );
  const pacer = newPacer();

  const outOfTime = () =>
    new ConnectorError({
      type: "rate_limited",
      message: `ClickHouse Cloud rate-limits P0's API key to ${RATE_LIMIT_REQUESTS} requests per 10 seconds, and this needs more calls than P0 can send in the time it has. Retry in a few minutes. If it keeps happening, a large organization can ask ClickHouse support to raise the key's limit.`,
      payload: { organizationId },
    });

  /** One Cloud API call in its turn, sent again after a 429 while there's time. */
  const send = async (request: Omit<CloudRequest, "key" | "log">) => {
    const key = await readKey();
    if (!pacing) return cloudRequest({ log, key, ...request });
    for (;;) {
      const wait = pacer.turn();
      if (pacer.elapsed() + wait > RATE_LIMIT_BUDGET) throw outOfTime();
      await sleep(wait);
      try {
        return await cloudRequest({ log, key, ...request });
      } catch (error) {
        if (!isTooManyRequests(error)) throw error;
        const delay = retryDelay(error.retryAfter);
        if (pacer.elapsed() + delay > RATE_LIMIT_BUDGET) throw error;
        log.warn(
          {
            method: request.method,
            path: request.path,
            retryAfter: error.retryAfter,
            delay,
          },
          "ClickHouse Cloud rate limited a request; sending it again after the wait"
        );
        await sleep(delay);
      }
    }
  };

  const organizationPath = `/v1/organizations/${segment(organizationId)}`;
  const servicePath = (serviceId: string) =>
    `${organizationPath}/services/${segment(serviceId)}`;
  const endpointsPath = (serviceId: string) =>
    `${servicePath(serviceId)}/query-api-endpoints`;

  const call = async <T>(
    what: string,
    schema: z.ZodType<T>,
    request: {
      method: Method;
      path: string;
      search?: Record<string, string>;
      body?: unknown;
    }
  ): Promise<T> => {
    const data = await send(request);
    return parseResponse({ log, schema, data, what });
  };

  const result = async <T>(
    what: string,
    schema: z.ZodType<T>,
    request: { method: Method; path: string; body?: unknown }
  ): Promise<T> => {
    const parsed: { result: T } = await call(what, envelope(schema), request);
    return parsed.result;
  };

  /** Every item of a listing that pages, following `nextCursor`. */
  const every = async <T>(
    what: string,
    item: z.ZodType<T>,
    { path, search }: { path: string; search: Record<string, string> }
  ): Promise<T[]> => {
    const pagesFrom = async (
      cursor: string | undefined,
      pages: number
    ): Promise<T[]> => {
      if (pages >= MAX_PAGES) {
        throw new ConnectorError({
          type: "unknown",
          message: `ClickHouse Cloud listed ${what} over more than ${MAX_PAGES} pages, more than P0 reads.`,
          payload: { what },
        });
      }
      const { result: listed, nextCursor } = await call(what, page(item), {
        method: "GET",
        path,
        search: { ...search, ...(cursor === undefined ? {} : { cursor }) },
      });
      return nextCursor
        ? [...listed, ...(await pagesFrom(nextCursor, pages + 1))]
        : listed;
    };
    return pagesFrom(undefined, 0);
  };

  /**
   * Every item of a listing the OpenAPI documents in one piece. One that says
   * it has more, by its `nextCursor` or its `totalCount`, fails as `unknown`:
   * read as whole, a role past the first page would look gone to a revoke,
   * and a service past it would drop out of the install's reports.
   */
  const whole = async <T>(
    what: string,
    listing: string,
    item: z.ZodType<T>,
    path: string
  ): Promise<T[]> => {
    const {
      result: items,
      nextCursor,
      totalCount,
    } = await call(what, unpaged(item), { method: "GET", path });
    const more =
      Boolean(nextCursor) ||
      (typeof totalCount === "number" && totalCount > items.length);
    if (!more) return items;
    log.warn(
      {
        what,
        items: items.length,
        totalCount,
        nextCursor: Boolean(nextCursor),
      },
      "ClickHouse Cloud paged a listing the connector reads whole"
    );
    throw new ConnectorError({
      type: "unknown",
      message: `ClickHouse Cloud paged the ${listing} listing, which P0 reads in one piece, so it can't tell what the later pages hold.`,
      payload: { what },
    });
  };

  /**
   * The organization's roles. A role that doesn't parse is dropped, with a
   * warning naming only its ID, unless it's `target`, the role the caller
   * acts on, its name can't be read, or it's one of `systemRoles`, ignoring
   * case: then the listing fails as `unknown`. Another P0 role that doesn't
   * parse is dropped too, so it can't stop the steps on every other
   * request's role.
   */
  const listRoles = async ({
    target,
    systemRoles = [],
  }: {
    target?: string;
    systemRoles?: readonly string[];
  } = {}): Promise<Role[]> => {
    const what = "the organization's roles";
    const neededSystemRoles = new Set(
      systemRoles.map((name) => name.toLowerCase())
    );
    const items = await whole(
      what,
      "roles",
      z.unknown(),
      `${organizationPath}/roles`
    );
    const parseRole = (item: unknown): Role | undefined => {
      const parsed = role.safeParse(item);
      if (parsed.success) return parsed.data;
      const { id, name, type } = roleHeader.parse(item);
      const needed =
        name === undefined ||
        name === target ||
        (type === "system" && neededSystemRoles.has(name.toLowerCase()));
      if (!needed) {
        log.warn({ roleId: id }, "dropped a role the connector can't read");
        return undefined;
      }
      log.warn(
        {
          what,
          roleId: id,
          // Where each issue is and its code, never a value.
          issues: parsed.error.issues.map(({ path, code }) => ({
            path: path.join("."),
            code,
          })),
        },
        "ClickHouse Cloud returned a role the connector can't read"
      );
      throw new ConnectorError({
        type: "unknown",
        message: `ClickHouse Cloud returned ${
          name === undefined ? "a role" : `the role ${name}`
        } in a shape P0 doesn't recognize.`,
        payload: { what },
      });
    };
    return compact(items.map(parseRole));
  };

  // The last key listing, which `keyUuid` reads rather than list them again.
  let listedKeys: ListedApiKey[] | undefined;

  const listKeys = async () => {
    listedKeys = await every("the organization's API keys", apiKey, {
      path: `${organizationPath}/keys`,
      search: {},
    });
    return listedKeys;
  };

  return {
    /** Reads the key, which every other call does first, so a failure here says the secret is the problem. */
    readKey,

    /** `GET /v1/organizations/{organizationId}`. */
    getOrganization: () =>
      result("the organization", organization, {
        method: "GET",
        path: organizationPath,
      }),

    /** `GET …/members`. */
    listMembers: () =>
      whole(
        "the organization's members",
        "members",
        member,
        `${organizationPath}/members`
      ),

    /** `GET …/services`, read whole. */
    listServices: () =>
      whole(
        "the organization's services",
        "services",
        service,
        `${organizationPath}/services`
      ),

    /** `GET …/services/{serviceId}`. */
    getService: (serviceId: string) =>
      result("a service", service, {
        method: "GET",
        path: servicePath(serviceId),
      }),

    /** `GET …/services/{serviceId}/query-api-endpoints`, every page. */
    listEndpoints: (serviceId: string): Promise<ListedEndpoint[]> =>
      every("a service's Query API endpoints", listedEndpoint, {
        path: endpointsPath(serviceId),
        search: { limit: String(ENDPOINT_PAGE_SIZE) },
      }),

    /** `GET …/keys`, every page. */
    listKeys,

    /**
     * The key's own UUID, which an endpoint's `apiKeyIds` takes, found among
     * the organization's keys once per key ID and kept for the process's
     * lifetime. It reads this client's last key listing when there is one,
     * such as the install's permission probe. Throws a
     * `dependency_violation` when no key, or more than one, matches.
     */
    keyUuid: async (): Promise<string> => {
      const key = await readKey();
      const cached = `${organizationId}/${key.keyId}`;
      const known = keyUuids.get(cached);
      if (known !== undefined) return known;
      const uuid = identifyKey(listedKeys ?? (await listKeys()), key);
      keyUuids.set(cached, uuid);
      return uuid;
    },

    /** `GET …/query-api-endpoints/{endpointId}`, for one of P0's. */
    getEndpoint: async (serviceId: string, { id, name }: Named) => {
      requireP0Endpoint(name);
      return result("a Query API endpoint", endpoint, {
        method: "GET",
        path: `${endpointsPath(serviceId)}/${segment(id)}`,
      });
    },

    /** `POST …/query-api-endpoints`, for one of P0's. */
    createEndpoint: async (serviceId: string, request: EndpointRequest) => {
      requireP0Endpoint(request.name);
      return result("the created Query API endpoint", endpoint, {
        method: "POST",
        path: endpointsPath(serviceId),
        body: request,
      });
    },

    /** `PUT …/query-api-endpoints/{endpointId}`, for one of P0's. */
    updateEndpoint: async (
      serviceId: string,
      { id, name }: Named,
      request: EndpointRequest
    ) => {
      requireP0Endpoint(name);
      requireP0Endpoint(request.name);
      return result("the updated Query API endpoint", endpoint, {
        method: "PUT",
        path: `${endpointsPath(serviceId)}/${segment(id)}`,
        body: request,
      });
    },

    /** `DELETE …/query-api-endpoints/{endpointId}`, for one of P0's. */
    deleteEndpoint: async (
      serviceId: string,
      { id, name }: Named
    ): Promise<void> => {
      requireP0Endpoint(name);
      await call("the deleted Query API endpoint", z.unknown(), {
        method: "DELETE",
        path: `${endpointsPath(serviceId)}/${segment(id)}`,
      });
    },

    /** Runs one of P0's endpoints at its `url`, and returns its rows. */
    runEndpoint: async (
      runnable: Runnable,
      queryVariables?: QueryVariables
    ): Promise<unknown[]> => {
      requireP0Endpoint(runnable.name);
      const { keyId, keySecret } = await readKey();
      return runEndpoint({
        log,
        key: { keyId, keySecret },
        endpoint: runnable,
        queryVariables,
      });
    },

    /** `GET …/roles`: every role, system and custom, that the connector can read or needs. */
    listRoles,

    /** `POST …/roles`, for one of P0's. */
    createRole: async (request: {
      name: string;
      actors: string[];
      policies: PolicyRequest[];
    }) => {
      requireP0Role(request.name);
      return result("the created role", role, {
        method: "POST",
        path: `${organizationPath}/roles`,
        body: request,
      });
    },

    /** `PATCH …/roles/{roleId}`, for one of P0's: replaces its actors or its policies. */
    updateRole: async (
      { id, name }: Named,
      patch: { actors?: string[]; policies?: PolicyRequest[] }
    ) => {
      requireP0Role(name);
      return result("the updated role", role, {
        method: "PATCH",
        path: `${organizationPath}/roles/${segment(id)}`,
        body: patch,
      });
    },

    /** `DELETE …/roles/{roleId}`, for one of P0's. */
    deleteRole: async ({ id, name }: Named): Promise<void> => {
      requireP0Role(name);
      await call("the deleted role", z.unknown(), {
        method: "DELETE",
        path: `${organizationPath}/roles/${segment(id)}`,
      });
    },
  };
};

export type CloudClient = ReturnType<typeof newCloudClient>;
