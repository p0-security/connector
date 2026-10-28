import { vi } from "vitest";
import { z } from "zod";

import { REQUIRED_SCOPES } from "../auth0/scopes.ts";

/**
 * One Auth0 tenant behind `fetch`: the token endpoint and the Management API
 * endpoints the connector calls, answering in the shapes Auth0's API reference
 * gives, over state a test can read and change.
 */

/** How long the tenant's access tokens last: Auth0's default, a day. */
export const TOKEN_LIFETIME_S = 24 * 60 * 60;

/** A request the connector sent, as Auth0 would see it. */
export type Auth0Call = {
  method: string;
  url: string;
  host: string;
  /** The path as sent, still percent-encoded. */
  path: string;
  query: Record<string, string>;
  /** Lowercased names, as `Headers` gives them. */
  headers: Record<string, string>;
  /** The body as sent, and parsed. */
  rawBody: string | undefined;
  body: unknown;
  redirect: string | undefined;
};

export type Auth0Reply =
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { throws: unknown };

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

/** The Management API failing a call, with its usual error body. */
export const failing = (
  status: number,
  message = REASONS[status] ?? "error",
  errorCode?: string,
  headers?: Record<string, string>
): Auth0Reply => ({
  status,
  body: {
    statusCode: status,
    error: REASONS[status] ?? "Error",
    message,
    ...(errorCode !== undefined ? { errorCode } : {}),
  },
  headers,
});

/** The token endpoint failing a call, with its OAuth error body. */
export const oauthFailing = (
  status: number,
  error: string,
  description: string
): Auth0Reply => ({
  status,
  body: { error, error_description: description },
});

const NOT_FOUND = failing(404);

const rolesBody = z.object({ roles: z.array(z.string()).min(1) });
const membersBody = z.object({ members: z.array(z.string()).min(1) });
const permissionsBody = z.object({
  permissions: z
    .array(
      z.object({
        resource_server_identifier: z.string(),
        permission_name: z.string(),
      })
    )
    .min(1),
});

const tokenBody = z.object({
  grant_type: z.literal("client_credentials"),
  client_id: z.string(),
  client_secret: z.string(),
  audience: z.string(),
});

const base64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** An access token shaped like Auth0's, whose payload carries `exp` and `scope`. */
export const accessToken = ({
  expiresAt,
  scopes,
  n = 1,
}: {
  expiresAt: number;
  scopes: readonly string[];
  n?: number;
}): string =>
  [
    base64url({ alg: "RS256", typ: "JWT", kid: "kid-1" }),
    base64url({
      iss: "https://acme.us.auth0.com/",
      sub: "client@clients",
      exp: Math.floor(expiresAt / 1000),
      scope: scopes.join(" "),
      gty: "client-credentials",
      jti: `token-${n}`,
    }),
    `c2lnbmF0dXJl${n}`,
  ].join(".");

/** A user in the fake tenant, with what's assigned to it directly. */
export type FakeUser = {
  user_id: string;
  email: string;
  connection: string;
  /** Role ids assigned to the user directly. */
  roles: string[];
  /** Permissions assigned to the user directly. */
  permissions: FakePermission[];
};

export type FakePermission = { api: string; name: string };

export type FakeRole = {
  id: string;
  name: string;
  /** The permissions the role gives. */
  permissions: FakePermission[];
};

export type FakeApi = {
  identifier: string;
  name: string;
  /** Auth0's own APIs, such as the Management API. */
  is_system?: boolean;
  scopes: { value: string; description?: string }[];
};

export type FakeOrganization = {
  id: string;
  name: string;
  /** Each member's user id, and the role ids it holds in the organization. */
  members: Map<string, string[]>;
};

/** The most items on one page, as Auth0 caps `per_page`. */
const MAX_PAGE_SIZE = 100;

/** How many items `page`/`per_page` reaches on `/organizations` before Auth0 refuses. */
const PAGE_PAGINATION_CAP = 1000;

const pageOf = <T>(items: T[], query: Record<string, string>): T[] => {
  const size = Math.min(Number(query.per_page ?? "50"), MAX_PAGE_SIZE);
  const page = Number(query.page ?? "0");
  return items.slice(page * size, page * size + size);
};

const sameApiPermission = (a: FakePermission, b: FakePermission) =>
  a.api === b.api && a.name === b.name;

const userJson = ({ user_id, email, connection }: FakeUser) => ({
  user_id,
  email,
  email_verified: true,
  identities: [
    {
      connection,
      provider:
        connection === "Username-Password-Authentication"
          ? "auth0"
          : connection,
      user_id: user_id.split("|")[1] ?? user_id,
      isSocial: false,
    },
  ],
  created_at: "2026-01-01T00:00:00.000Z",
});

type Options = {
  tenant: string;
  clientId: string;
  /** The client secret the tenant accepts. Any other is refused. */
  clientSecret: string;
  /** The scopes the client is granted on the Management API. */
  scopes?: readonly string[];
  /** How a write answers when what it adds is already there. By default, it succeeds. */
  alreadyAssigned?: Auth0Reply;
};

export const newFakeAuth0 = (options: Options) => {
  const { tenant, clientId, clientSecret, scopes = REQUIRED_SCOPES } = options;
  const calls: Auth0Call[] = [];
  /** Every access token issued, in order. */
  const tokens: string[] = [];
  /** The access tokens the tenant still accepts, and until when. */
  const live = new Map<string, number>();
  let interceptor: ((call: Auth0Call) => Auth0Reply | undefined) | undefined;
  const state = { scopes: [...scopes] };
  const users: FakeUser[] = [];
  const roles: FakeRole[] = [];
  const apis: FakeApi[] = [];
  const organizations: FakeOrganization[] = [];

  const findUser = (id: string | undefined) =>
    users.find(({ user_id }) => user_id === id);
  const findRole = (id: string) => roles.find((role) => role.id === id);
  const findOrganization = (id: string | undefined) =>
    organizations.find((organization) => organization.id === id);

  /** The permissions a user holds, with where each comes from. */
  const effectivePermissions = (user: FakeUser) => {
    const held: (FakePermission & { sources: string[] })[] = [];
    const add = (permission: FakePermission, source: string) => {
      const found = held.find((other) => sameApiPermission(other, permission));
      if (found) {
        if (!found.sources.includes(source)) found.sources.push(source);
      } else held.push({ ...permission, sources: [source] });
    };
    for (const permission of user.permissions) add(permission, "direct");
    for (const id of user.roles) {
      for (const permission of findRole(id)?.permissions ?? []) {
        add(permission, "roles");
      }
    }
    return held.map(({ api, name, sources }) => ({
      resource_server_identifier: api,
      resource_server_name: apis.find(({ identifier }) => identifier === api)
        ?.name,
      permission_name: name,
      description: name,
      sources,
    }));
  };

  /** As Auth0 answers it: one API at a time, with a checkpoint. */
  const listEffectivePermissions = (
    user: FakeUser,
    query: Record<string, string>
  ): Auth0Reply => {
    const api = query.resource_server_identifier;
    if (!api) {
      return failing(
        400,
        "Query validation error: 'Missing required property: resource_server_identifier'.",
        "invalid_query_string"
      );
    }
    const held = effectivePermissions(user).filter(
      ({ resource_server_identifier }) => resource_server_identifier === api
    );
    const take = Math.min(Number(query.take ?? "50"), MAX_PAGE_SIZE);
    const start = query.from === undefined ? 0 : Number(query.from);
    const slice = held.slice(start, start + take);
    const end = start + slice.length;
    return {
      status: 200,
      body: {
        permissions: slice,
        ...(end < held.length ? { next: String(end) } : {}),
      },
    };
  };

  const listOrganizations = (query: Record<string, string>): Auth0Reply => {
    if (query.take !== undefined) {
      const take = Math.min(Number(query.take), MAX_PAGE_SIZE);
      const start = query.from === undefined ? 0 : Number(query.from);
      const slice = organizations.slice(start, start + take);
      const end = start + slice.length;
      return {
        status: 200,
        body: {
          organizations: slice.map(({ id, name }) => ({
            id,
            name,
            display_name: name,
          })),
          ...(end < organizations.length ? { next: String(end) } : {}),
        },
      };
    }
    const size = Math.min(Number(query.per_page ?? "50"), MAX_PAGE_SIZE);
    if ((Number(query.page ?? "0") + 1) * size > PAGE_PAGINATION_CAP) {
      return failing(
        400,
        "Requesting page exceeds the allowed maximum of 1000 records"
      );
    }
    return {
      status: 200,
      body: pageOf(organizations, query).map(({ id, name }) => ({ id, name })),
    };
  };

  const isLive = (bearer: string | undefined) => {
    const expiresAt = bearer === undefined ? undefined : live.get(bearer);
    return expiresAt !== undefined && Date.now() < expiresAt;
  };

  const exchange = ({ body }: Auth0Call): Auth0Reply => {
    const parsed = tokenBody.safeParse(body);
    if (!parsed.success) {
      return oauthFailing(400, "invalid_request", "Missing required parameter");
    }
    const { client_id, client_secret, audience } = parsed.data;
    if (client_id !== clientId || client_secret !== clientSecret) {
      return oauthFailing(401, "access_denied", "Unauthorized");
    }
    if (audience !== `https://${tenant}/api/v2/`) {
      return oauthFailing(
        403,
        "access_denied",
        `Client is not authorized to access "${audience}". You need to create a "client-grant" associated to this API.`
      );
    }
    const expiresAt = Date.now() + TOKEN_LIFETIME_S * 1000;
    const issued = accessToken({
      expiresAt,
      scopes: state.scopes,
      n: tokens.length + 1,
    });
    tokens.push(issued);
    live.set(issued, expiresAt);
    return {
      status: 200,
      body: {
        access_token: issued,
        scope: state.scopes.join(" "),
        expires_in: TOKEN_LIFETIME_S,
        token_type: "Bearer",
      },
    };
  };

  /** Answers a Management API call, once its token has been checked. */
  const management = (call: Auth0Call, segments: string[]): Auth0Reply => {
    const { method, query } = call;
    const [first, second, third, fourth, fifth, ...rest] = segments;
    if (rest.length > 0) return NOT_FOUND;

    if (method === "GET" && first === "users-by-email" && !second) {
      // Case-sensitive, as Auth0's is.
      return {
        status: 200,
        body: users.filter(({ email }) => email === query.email).map(userJson),
      };
    }
    if (method === "GET" && first === "roles" && !second) {
      return {
        status: 200,
        body: pageOf(roles, query).map(({ id, name }) => ({
          id,
          name,
          description: name,
        })),
      };
    }
    if (method === "GET" && first === "resource-servers" && !second) {
      return { status: 200, body: pageOf(apis, query) };
    }
    if (method === "GET" && first === "organizations" && !second) {
      return listOrganizations(query);
    }

    if (first === "users" && second !== undefined) {
      const user = findUser(second);
      if (!user)
        return failing(404, "The user does not exist.", "inexistent_user");
      if (method === "GET" && third === undefined) {
        return { status: 200, body: userJson(user) };
      }
      if (method === "GET" && third === "roles" && !fourth) {
        return {
          status: 200,
          body: pageOf(
            user.roles.flatMap((id) => {
              const role = findRole(id);
              return role ? [{ id: role.id, name: role.name }] : [];
            }),
            query
          ),
        };
      }
      if (method === "GET" && third === "effective-permissions" && !fourth) {
        return listEffectivePermissions(user, query);
      }
      if (method === "GET" && third === "organizations" && !fourth) {
        return {
          status: 200,
          body: pageOf(
            organizations
              .filter(({ members }) => members.has(user.user_id))
              .map(({ id, name }) => ({ id, name })),
            query
          ),
        };
      }
      return writeUser(call, user, third) ?? NOT_FOUND;
    }

    if (first === "organizations" && second !== undefined) {
      const organization = findOrganization(second);
      if (!organization) {
        return failing(
          404,
          "No organization found by that id or name",
          "inexistent_organization"
        );
      }
      if (third === "members" && fourth !== undefined && fifth === "roles") {
        const memberRoles = organization.members.get(fourth);
        if (memberRoles === undefined) {
          return failing(404, "The user is not a member of the organization.");
        }
        if (method === "GET") {
          return {
            status: 200,
            body: pageOf(
              memberRoles.flatMap((id) => {
                const role = findRole(id);
                return role ? [{ id: role.id, name: role.name }] : [];
              }),
              query
            ),
          };
        }
      }
      return (
        writeOrganization(call, organization, third, fourth, fifth) ?? NOT_FOUND
      );
    }
    return NOT_FOUND;
  };

  /** The ids in a `{ roles: [...] }` body, or `undefined` for any other body. */
  const roleIdsOf = (body: unknown) => {
    const parsed = rolesBody.safeParse(body);
    return parsed.success ? parsed.data.roles : undefined;
  };

  const writeUser = (
    { method, body }: Auth0Call,
    user: FakeUser,
    what: string | undefined
  ): Auth0Reply | undefined => {
    if (what === "roles" && (method === "POST" || method === "DELETE")) {
      const ids = roleIdsOf(body);
      if (!ids) return failing(400, "Payload validation error", "invalid_body");
      if (method === "DELETE") {
        user.roles = user.roles.filter((id) => !ids.includes(id));
        return { status: 204 };
      }
      if (ids.some((id) => !findRole(id))) {
        return failing(404, "One or more of the roles do not exist");
      }
      // What Auth0 answers for a role already assigned isn't documented.
      if (
        options.alreadyAssigned !== undefined &&
        ids.some((id) => user.roles.includes(id))
      ) {
        return options.alreadyAssigned;
      }
      for (const id of ids) if (!user.roles.includes(id)) user.roles.push(id);
      return { status: 204 };
    }
    if (what === "permissions" && (method === "POST" || method === "DELETE")) {
      const parsed = permissionsBody.safeParse(body);
      if (!parsed.success) {
        return failing(400, "Payload validation error", "invalid_body");
      }
      const wanted = parsed.data.permissions.map(
        ({ resource_server_identifier, permission_name }) => ({
          api: resource_server_identifier,
          name: permission_name,
        })
      );
      if (method === "DELETE") {
        // Only the direct assignment: a role's permissions belong to the role.
        user.permissions = user.permissions.filter(
          (held) =>
            !wanted.some((permission) => sameApiPermission(held, permission))
        );
        return { status: 204 };
      }
      const defined = (permission: FakePermission) =>
        apis.some(
          ({ identifier, scopes: apiScopes }) =>
            identifier === permission.api &&
            apiScopes.some(({ value }) => value === permission.name)
        );
      if (!wanted.every(defined)) {
        return failing(
          404,
          "Resource server not found",
          "inexistent_resource_server"
        );
      }
      const held = (permission: FakePermission) =>
        user.permissions.some((other) => sameApiPermission(other, permission));
      if (options.alreadyAssigned !== undefined && wanted.some(held)) {
        return options.alreadyAssigned;
      }
      for (const permission of wanted) {
        if (!held(permission)) user.permissions.push(permission);
      }
      return { status: 201 };
    }
    return undefined;
  };

  const writeOrganization = (
    { method, body }: Auth0Call,
    organization: FakeOrganization,
    third: string | undefined,
    fourth: string | undefined,
    fifth: string | undefined
  ): Auth0Reply | undefined => {
    if (method !== "POST" && method !== "DELETE") return undefined;
    const { members } = organization;
    if (third === "members" && fourth === undefined) {
      const parsed = membersBody.safeParse(body);
      if (!parsed.success) {
        return failing(400, "Payload validation error", "invalid_body");
      }
      const ids = parsed.data.members;
      if (method === "DELETE") {
        for (const id of ids) members.delete(id);
        return { status: 204 };
      }
      if (ids.some((id) => !findUser(id))) {
        return failing(404, "The user does not exist.", "inexistent_user");
      }
      if (
        options.alreadyAssigned !== undefined &&
        ids.some((id) => members.has(id))
      ) {
        return options.alreadyAssigned;
      }
      for (const id of ids) if (!members.has(id)) members.set(id, []);
      return { status: 204 };
    }
    if (third === "members" && fourth !== undefined && fifth === "roles") {
      const held = members.get(fourth);
      if (held === undefined) {
        return failing(404, "The user is not a member of the organization.");
      }
      const ids = roleIdsOf(body);
      if (!ids) return failing(400, "Payload validation error", "invalid_body");
      if (method === "DELETE") {
        members.set(
          fourth,
          held.filter((id) => !ids.includes(id))
        );
        return { status: 204 };
      }
      if (ids.some((id) => !findRole(id))) {
        return failing(404, "One or more of the roles do not exist");
      }
      if (
        options.alreadyAssigned !== undefined &&
        ids.some((id) => held.includes(id))
      ) {
        return options.alreadyAssigned;
      }
      members.set(fourth, [...held, ...ids.filter((id) => !held.includes(id))]);
      return { status: 204 };
    }
    return undefined;
  };

  const answer = (call: Auth0Call): Auth0Reply => {
    if (call.host !== tenant) return { throws: new TypeError("fetch failed") };
    if (call.method === "POST" && call.path === "/oauth/token") {
      return exchange(call);
    }
    const [api, version, ...segments] = call.path
      .split("/")
      .filter(Boolean)
      .map(decodeURIComponent);
    if (api !== "api" || version !== "v2") return NOT_FOUND;
    if (!isLive(call.headers.authorization?.replace(/^Bearer /, ""))) {
      return failing(401, "Invalid token", "invalid_token");
    }
    return management(call, segments);
  };

  const fetch = vi.fn<typeof globalThis.fetch>(async (resource, init) => {
    const url = new URL(
      resource instanceof Request ? resource.url : resource.toString()
    );
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    const call: Auth0Call = {
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

  const isExchange = ({ path }: Auth0Call) => path === "/oauth/token";

  return {
    /** Stub the global `fetch` with this, and no real network call is made. */
    fetch,
    /** The scopes the client is granted, to read or to change. */
    state,
    /** The tenant's users, roles, APIs and organizations, to read or to change. */
    users,
    roles,
    apis,
    organizations,
    /** Every request sent, in order. */
    calls,
    tokens,
    /** The tenant stops accepting every access token it issued. */
    revokeTokens: () => live.clear(),
    /** Answers a call some other way, whenever `reply` returns an answer. */
    intercept: (reply: (call: Auth0Call) => Auth0Reply | undefined) => {
      interceptor = reply;
    },
    /** The token exchanges sent. */
    exchanges: () => calls.filter(isExchange),
    /** Every other request sent: the ones that carry an access token. */
    apiCalls: () => calls.filter((call) => !isExchange(call)),
    /** What was asked to change: every request but a `GET` and the token exchange. */
    writes: () =>
      calls
        .filter((call) => call.method !== "GET" && !isExchange(call))
        .map(({ method, path, body }) => ({ method, path, body })),
    /** The access token each of those carried, in order. */
    bearers: () =>
      calls
        .filter((call) => !isExchange(call))
        .map(({ headers }) => headers.authorization?.replace(/^Bearer /, "")),
  };
};

export type FakeAuth0 = ReturnType<typeof newFakeAuth0>;

/** Matches a call by its method and its path, for {@link FakeAuth0.intercept}. */
export const isCall =
  (method: string, path: RegExp | string) =>
  (call: Auth0Call): boolean =>
    call.method === method &&
    (typeof path === "string" ? call.path === path : path.test(call.path));
