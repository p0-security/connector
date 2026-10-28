import { z } from "zod";

import {
  type Method,
  type TenantCall,
  auth0Request,
  parseResponse,
  segment,
} from "./api.ts";

/** The most items Auth0 returns on one page. */
export const PAGE_SIZE = 100;

/** One Management API call, read with `schema`. */
const send = async <T>(
  { log, tenant, accessToken }: TenantCall,
  {
    method,
    path,
    query,
    body,
    schema,
    what,
  }: {
    method: Method;
    path: string;
    query?: Record<string, string>;
    body?: unknown;
    schema: z.ZodType<T>;
    what: string;
  }
): Promise<T> => {
  const search = query ? `?${new URLSearchParams(query).toString()}` : "";
  const data = await auth0Request({
    log,
    tenant,
    method,
    path: `/api/v2${path}${search}`,
    accessToken,
    body,
  });
  return parseResponse({ log, schema, data, what });
};

/**
 * Every item of a `page`/`per_page` listing. It stops at the first page that
 * isn't full, so a listing of exactly a page's worth ends with an empty one.
 */
const everyPage = async <T>(
  read: (page: number) => Promise<T[]>
): Promise<T[]> => {
  const found: T[] = [];
  for (let page = 0; ; page++) {
    const items = await read(page);
    found.push(...items);
    if (items.length < PAGE_SIZE) return found;
  }
};

const pageQuery = (page: number) => ({
  page: String(page),
  per_page: String(PAGE_SIZE),
});

/** An Auth0 user, with the connection of its primary identity. */
export type Auth0User = {
  userId: string;
  email: string | undefined;
  /** The connection of the user's first identity, which is its primary one. */
  connection: string | undefined;
};

const user = z
  .object({
    user_id: z.string().min(1),
    email: z.string().nullish(),
    identities: z
      .array(z.object({ connection: z.string().nullish() }))
      .nullish(),
  })
  .transform(({ user_id, email, identities }): Auth0User => ({
    userId: user_id,
    email: email ?? undefined,
    connection: identities?.[0]?.connection ?? undefined,
  }));

/**
 * `GET /users-by-email`: every user with exactly this email, one per unlinked
 * identity. The match is case-sensitive.
 */
export const getUsersByEmail = (api: TenantCall, email: string) =>
  send(api, {
    method: "GET",
    path: "/users-by-email",
    query: { email },
    schema: z.array(user),
    what: "the users with an email",
  });

/** `GET /users/{id}`: one user. A 404 when there's none. */
export const getUser = (api: TenantCall, userId: string) =>
  send(api, {
    method: "GET",
    path: `/users/${segment(userId)}`,
    query: { fields: "user_id,email,identities", include_fields: "true" },
    schema: user,
    what: "a user",
  });

/** A role, or any other item that's an id and a name. */
export type Named = { id: string; name: string };

const named = z.object({ id: z.string().min(1), name: z.string() });

/** `GET /roles`: every tenant role. */
export const listRoles = (api: TenantCall): Promise<Named[]> =>
  everyPage((page) =>
    send(api, {
      method: "GET",
      path: "/roles",
      query: pageQuery(page),
      schema: z.array(named),
      what: "a page of roles",
    })
  );

/** An API, and the permissions it defines. */
export type ResourceServer = {
  identifier: string;
  name: string;
  permissions: { value: string; description: string | undefined }[];
};

const resourceServer = z
  .object({
    identifier: z.string().min(1),
    name: z.string().nullish(),
    is_system: z.boolean().nullish(),
    scopes: z
      .array(
        z.object({
          value: z.string().min(1),
          description: z.string().nullish(),
        })
      )
      .nullish(),
  })
  // A system API reads as `undefined`, which the listing drops after paging,
  // so a page's length still says whether another follows.
  .transform(
    ({ identifier, name, is_system, scopes }): ResourceServer | undefined =>
      is_system
        ? undefined
        : {
            identifier,
            name: name ?? identifier,
            permissions: (scopes ?? []).map(({ value, description }) => ({
              value,
              description: description ?? undefined,
            })),
          }
  );

/**
 * `GET /resource-servers`: every API a user can be given permissions on.
 * Auth0's own system APIs, such as the Management API, are left out: Auth0
 * refuses to assign their permissions to a user ("System APIs may not be
 * used", seen on a live tenant).
 */
export const listResourceServers = async (
  api: TenantCall
): Promise<ResourceServer[]> =>
  (
    await everyPage((page) =>
      send(api, {
        method: "GET",
        path: "/resource-servers",
        query: pageQuery(page),
        schema: z.array(resourceServer),
        what: "a page of APIs",
      })
    )
  ).filter((server) => server !== undefined);

const organizationPage = z.object({
  organizations: z.array(named),
  next: z.string().nullish(),
});

/**
 * `GET /organizations`, with checkpoint pagination (`from`/`take`), which has
 * no cap. `page`/`per_page` stops at 1000 organizations.
 *
 * Auth0 allows this endpoint 5 calls in a burst and 50 a minute, so it's only
 * called to list, never to look one up.
 */
export const listOrganizations = async (api: TenantCall): Promise<Named[]> => {
  const found: Named[] = [];
  let from: string | undefined;
  for (;;) {
    const { organizations, next } = await send(api, {
      method: "GET",
      path: "/organizations",
      query: { take: String(PAGE_SIZE), ...(from ? { from } : {}) },
      schema: organizationPage,
      what: "a page of organizations",
    });
    found.push(...organizations);
    if (!next || organizations.length === 0) return found;
    from = next;
  }
};

/** `GET /users/{id}/roles`: the roles assigned to the user directly. */
export const listUserRoles = (
  api: TenantCall,
  userId: string
): Promise<Named[]> =>
  everyPage((page) =>
    send(api, {
      method: "GET",
      path: `/users/${segment(userId)}/roles`,
      query: pageQuery(page),
      schema: z.array(named),
      what: "a page of the user's roles",
    })
  );

/** A permission the user holds, and how. */
export type UserPermission = {
  resourceServerIdentifier: string;
  permissionName: string;
  /** Whether it's assigned to the user directly, whatever roles also give it. */
  direct: boolean;
};

const effectivePermission = z
  .object({
    resource_server_identifier: z.string().min(1),
    permission_name: z.string().min(1),
    sources: z.array(z.string()).nullish(),
  })
  .transform(
    ({
      resource_server_identifier,
      permission_name,
      sources,
    }): UserPermission => ({
      resourceServerIdentifier: resource_server_identifier,
      permissionName: permission_name,
      direct: (sources ?? []).some((value) => value.toLowerCase() === "direct"),
    })
  );

const effectivePermissionPage = z.object({
  permissions: z.array(effectivePermission),
  next: z.string().nullish(),
});

/**
 * `GET /users/{id}/effective-permissions`: every permission the user holds on
 * one API, with where each comes from. `GET /users/{id}/permissions` can't
 * tell a direct permission from one a directly assigned role gives. Auth0
 * requires the API and pages with a checkpoint (`from`/`take`).
 */
export const listUserPermissions = async (
  api: TenantCall,
  userId: string,
  resourceServerIdentifier: string
): Promise<UserPermission[]> => {
  const found: UserPermission[] = [];
  let from: string | undefined;
  for (;;) {
    const { permissions, next } = await send(api, {
      method: "GET",
      path: `/users/${segment(userId)}/effective-permissions`,
      query: {
        resource_server_identifier: resourceServerIdentifier,
        take: String(PAGE_SIZE),
        ...(from ? { from } : {}),
      },
      schema: effectivePermissionPage,
      what: "a page of the user's permissions",
    });
    found.push(...permissions);
    if (!next || permissions.length === 0) return found;
    from = next;
  }
};

/** `GET /users/{id}/organizations`: the organizations the user is a member of. */
export const listUserOrganizations = (
  api: TenantCall,
  userId: string
): Promise<Named[]> =>
  everyPage((page) =>
    send(api, {
      method: "GET",
      path: `/users/${segment(userId)}/organizations`,
      query: pageQuery(page),
      schema: z.array(named),
      what: "a page of the user's organizations",
    })
  );

/** `GET /organizations/{id}/members/{user}/roles`: the member's roles in the organization. */
export const listMemberRoles = (
  api: TenantCall,
  organizationId: string,
  userId: string
): Promise<Named[]> =>
  everyPage((page) =>
    send(api, {
      method: "GET",
      path: `/organizations/${segment(organizationId)}/members/${segment(userId)}/roles`,
      query: pageQuery(page),
      schema: z.array(named),
      what: "a page of the member's roles",
    })
  );

/** `POST /users/{id}/roles`: assigns the roles to the user directly. */
export const assignUserRoles = (
  api: TenantCall,
  userId: string,
  roleIds: string[]
) =>
  send(api, {
    method: "POST",
    path: `/users/${segment(userId)}/roles`,
    body: { roles: roleIds },
    schema: z.unknown(),
    what: "the role assignment",
  });

/** `DELETE /users/{id}/roles`: removes the roles assigned to the user directly. */
export const removeUserRoles = (
  api: TenantCall,
  userId: string,
  roleIds: string[]
) =>
  send(api, {
    method: "DELETE",
    path: `/users/${segment(userId)}/roles`,
    body: { roles: roleIds },
    schema: z.unknown(),
    what: "the role removal",
  });

/** `POST /organizations/{id}/members`: adds the users to the organization. */
export const addOrganizationMembers = (
  api: TenantCall,
  organizationId: string,
  userIds: string[]
) =>
  send(api, {
    method: "POST",
    path: `/organizations/${segment(organizationId)}/members`,
    body: { members: userIds },
    schema: z.unknown(),
    what: "the membership",
  });

/** `DELETE /organizations/{id}/members`: removes the users from the organization. */
export const removeOrganizationMembers = (
  api: TenantCall,
  organizationId: string,
  userIds: string[]
) =>
  send(api, {
    method: "DELETE",
    path: `/organizations/${segment(organizationId)}/members`,
    body: { members: userIds },
    schema: z.unknown(),
    what: "the membership's removal",
  });

/** `POST /organizations/{id}/members/{user}/roles`: assigns tenant roles to the member, in the organization. */
export const assignMemberRoles = (
  api: TenantCall,
  organizationId: string,
  userId: string,
  roleIds: string[]
) =>
  send(api, {
    method: "POST",
    path: `/organizations/${segment(organizationId)}/members/${segment(userId)}/roles`,
    body: { roles: roleIds },
    schema: z.unknown(),
    what: "the member's role assignment",
  });

/** `DELETE /organizations/{id}/members/{user}/roles`: removes the member's roles in the organization. */
export const removeMemberRoles = (
  api: TenantCall,
  organizationId: string,
  userId: string,
  roleIds: string[]
) =>
  send(api, {
    method: "DELETE",
    path: `/organizations/${segment(organizationId)}/members/${segment(userId)}/roles`,
    body: { roles: roleIds },
    schema: z.unknown(),
    what: "the member's role removal",
  });

/** A permission an API defines, as the user permission endpoints take it. */
export type PermissionRef = {
  resourceServerIdentifier: string;
  permissionName: string;
};

const permissionsBody = (permissions: PermissionRef[]) => ({
  permissions: permissions.map(
    ({ resourceServerIdentifier, permissionName }) => ({
      resource_server_identifier: resourceServerIdentifier,
      permission_name: permissionName,
    })
  ),
});

/** `POST /users/{id}/permissions`: assigns the permissions to the user directly. */
export const assignUserPermissions = (
  api: TenantCall,
  userId: string,
  permissions: PermissionRef[]
) =>
  send(api, {
    method: "POST",
    path: `/users/${segment(userId)}/permissions`,
    body: permissionsBody(permissions),
    schema: z.unknown(),
    what: "the permission assignment",
  });

/**
 * `DELETE /users/{id}/permissions`: removes the permissions assigned to the
 * user directly. One a role gives belongs to the role, and stays.
 */
export const removeUserPermissions = (
  api: TenantCall,
  userId: string,
  permissions: PermissionRef[]
) =>
  send(api, {
    method: "DELETE",
    path: `/users/${segment(userId)}/permissions`,
    body: permissionsBody(permissions),
    schema: z.unknown(),
    what: "the permission removal",
  });
