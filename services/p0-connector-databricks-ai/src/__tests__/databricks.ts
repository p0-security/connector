import { DBSQL_MCP_PATH } from "../install/probe.ts";
import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  DEPLOYMENT_NAME,
  type FakeResponse,
  SP_SCIM_ID,
  WORKSPACE_ID,
  jsonResponse,
} from "./http.ts";

type Principal = {
  id: string;
  applicationId: string;
  displayName?: string;
  active?: boolean;
  roles?: { value: string }[];
};

/** A federation policy on a service principal, as the fake stores it. */
type FederationPolicy = { policy_id: string; oidc_policy: unknown };

/** How the fake fails one call: a status, with an error code or a default one. */
export type Failure = number | { status: number; errorCode: string };

type Assignment = {
  principal: {
    principal_id?: number;
    service_principal_name?: string;
    user_name?: string;
  };
  permissions: string[];
};

/** One call to the Databricks SQL MCP server, as the fake saw it. */
export type McpCall = {
  method: string;
  accept?: string;
  sessionId?: string;
};

/** How the fake MCP server answers one call. */
export type McpAnswer = {
  status: number;
  sessionId?: string;
  /** An event stream that never ends, as a server holding it open would send. */
  endlessBody?: boolean;
};

/** The connector's own service principal, with account admin. */
export const OWN_PRINCIPAL: Principal = {
  id: SP_SCIM_ID,
  applicationId: APPLICATION_ID,
  displayName: "p0-connector",
  roles: [{ value: "account_admin" }],
};

/**
 * A Databricks account as the fake serves it. Each test changes what it
 * needs before calling the connector.
 */
export const fakeAccount = () => ({
  servicePrincipals: [OWN_PRINCIPAL],
  users: [] as { id: string; userName: string }[],
  groups: [] as { id: string; displayName: string; members: string[] }[],
  metastores: [] as { metastore_id: string; name: string; owner?: string }[],
  workspaces: [
    {
      workspace_id: Number(WORKSPACE_ID),
      workspace_name: "analytics",
      deployment_name: DEPLOYMENT_NAME,
      workspace_status: "RUNNING",
    },
  ] as Record<string, unknown>[],
  /** The account-level permission assignments on `WORKSPACE_ID`. */
  assignments: [] as Assignment[],
  /** Federation policies, by account SCIM ID of the service principal. */
  policies: {} as Record<string, FederationPolicy[]>,
  /** Direct workspace entitlements on `WORKSPACE_ID`, by account SCIM ID. */
  entitlements: {} as Record<string, string[]>,
  /** Account API calls to refuse, as `"<METHOD> <path>"` to status. */
  refuse: {} as Record<string, number>,
  /**
   * Any call to fail before it changes anything, as `"<METHOD> <pathname>"`
   * (the full path, without the query) to how it fails.
   */
  fail: {} as Record<string, Failure>,
  /** How many service principals the fake has created. */
  created: 0,
  /** SQL warehouses in `WORKSPACE_ID`. */
  warehouses: [] as { id: string; name: string; warehouse_type: string }[],
  /** Each warehouse's access list, by warehouse ID. */
  warehouseAcl: {} as Record<
    string,
    { service_principal_name: string; permission_level: string }[]
  >,
  /** The metastore's Unity Catalog objects. */
  uc: {
    catalogs: [] as string[],
    schemas: [] as { catalog: string; name: string }[],
    objects: [] as {
      kind: "functions" | "tables" | "volumes";
      catalog: string;
      schema: string;
      name: string;
      owner: string;
    }[],
  },
  /**
   * Direct Unity Catalog privileges, by `<type>:<full name>` (lowercased)
   * and then by principal (lowercased).
   */
  grants: {} as Record<string, Record<string, string[]>>,
  /** Answers MCP calls in order. The last answer repeats. */
  mcp: [{ status: 200, sessionId: "session-1" }] as McpAnswer[],
  /** Every MCP call, in order. */
  mcpCalls: [] as McpCall[],
});

export type FakeAccount = ReturnType<typeof fakeAccount>;

const error = (status: number, error_code: string) =>
  jsonResponse({ error_code, message: "refused" }, { status });

const NOT_FOUND = () => error(404, "RESOURCE_DOES_NOT_EXIST");

/** The value of a SCIM filter `<attribute> eq "<value>"`, unescaped. */
const filterValue = (filter: string | null, attribute: string) => {
  const match = filter?.match(/^(\w+) eq "(.*)"$/);
  if (!match || match[1] !== attribute) return undefined;
  return match[2]?.replace(/\\(["\\])/g, "$1");
};

const same = (a: string | undefined, b: string | undefined) =>
  a !== undefined && b !== undefined && a.toLowerCase() === b.toLowerCase();

const mcpResponse = (answer: McpAnswer): FakeResponse => {
  const { status, sessionId, endlessBody } = answer;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
    body: endlessBody ? new ReadableStream({ start: () => {} }) : null,
    text: () => new Promise<string>(() => {}),
  };
};

const answerMcp = (account: FakeAccount, init: RequestInit) => {
  const headers = init.headers as Record<string, string>;
  const { method } = JSON.parse(init.body as string) as { method: string };
  account.mcpCalls.push({
    method,
    accept: headers.Accept,
    sessionId: headers["Mcp-Session-Id"],
  });
  const answer = account.mcp[account.mcpCalls.length - 1] ?? account.mcp.at(-1);
  return mcpResponse(answer ?? { status: 200 });
};

const answerAccount = (
  account: FakeAccount,
  method: string,
  path: string,
  query: URLSearchParams,
  body: string | undefined
) => {
  const refused = account.refuse[`${method} ${path}`];
  if (refused) return error(refused, "PERMISSION_DENIED");
  const filter = query.get("filter");
  const list = (resources: unknown[]) =>
    jsonResponse({ totalResults: resources.length, Resources: resources });

  if (method === "GET" && path === "/scim/v2/ServicePrincipals") {
    const applicationId = filterValue(filter, "applicationId");
    const displayName = filterValue(filter, "displayName");
    return list(
      account.servicePrincipals
        .filter(
          (p) =>
            same(p.applicationId, applicationId) ||
            same(p.displayName, displayName)
        )
        .map(({ roles: _, ...principal }) => principal)
    );
  }
  if (method === "GET" && path === "/scim/v2/Users") {
    const userName = filterValue(filter, "userName");
    return list(account.users.filter((u) => same(u.userName, userName)));
  }
  if (method === "GET" && path === "/scim/v2/Groups") {
    const displayName = filterValue(filter, "displayName");
    return list(
      account.groups
        .filter((g) => same(g.displayName, displayName))
        .map(({ id, displayName }) => ({ id, displayName }))
    );
  }
  const principal = path.match(/^\/scim\/v2\/ServicePrincipals\/(\d+)$/);
  if (method === "GET" && principal) {
    const found = account.servicePrincipals.find((p) => p.id === principal[1]);
    return found ? jsonResponse(found) : NOT_FOUND();
  }
  const group = path.match(/^\/scim\/v2\/Groups\/(\d+)$/);
  if (method === "GET" && group) {
    const found = account.groups.find((g) => g.id === group[1]);
    return found
      ? jsonResponse({
          id: found.id,
          displayName: found.displayName,
          members: found.members.map((value) => ({ value })),
        })
      : NOT_FOUND();
  }
  if (method === "GET" && path === "/workspaces") {
    return jsonResponse(account.workspaces);
  }
  if (method === "GET" && path === "/metastores") {
    return jsonResponse({ metastores: account.metastores });
  }
  const workspace = path.match(/^\/workspaces\/(\d+)$/);
  if (method === "GET" && workspace) {
    const found = account.workspaces.find(
      (w) => String(w.workspace_id) === workspace[1]
    );
    return found ? jsonResponse(found) : NOT_FOUND();
  }
  if (
    method === "GET" &&
    path === `/workspaces/${WORKSPACE_ID}/permissionassignments`
  ) {
    return jsonResponse({ permission_assignments: account.assignments });
  }
  const assign = path.match(
    new RegExp(
      `^/workspaces/${WORKSPACE_ID}/permissionassignments/principals/(\\d+)$`
    )
  );
  if (method === "PUT" && assign) {
    const { permissions } = JSON.parse(body ?? "{}") as {
      permissions: string[];
    };
    account.assignments = [
      ...account.assignments.filter(
        (a) => String(a.principal.principal_id) !== assign[1]
      ),
      { principal: { principal_id: Number(assign[1]) }, permissions },
    ];
    return jsonResponse({ permissions });
  }
  if (method === "DELETE" && assign) {
    const before = account.assignments.length;
    account.assignments = account.assignments.filter(
      (a) => String(a.principal.principal_id) !== assign[1]
    );
    if (account.assignments.length === before) return NOT_FOUND();
    delete account.entitlements[assign[1] ?? ""];
    return jsonResponse({});
  }

  if (method === "POST" && path === "/scim/v2/ServicePrincipals") {
    const { displayName, active } = JSON.parse(body ?? "{}") as {
      displayName: string;
      active: boolean;
    };
    account.created += 1;
    const created: Principal = {
      id: String(8_000_000_000_000_000 + account.created),
      applicationId: `00000000-0000-4000-8000-${String(account.created).padStart(12, "0")}`,
      displayName,
      active,
    };
    account.servicePrincipals.push(created);
    return jsonResponse(created, { status: 201 });
  }
  if (method === "DELETE" && principal) {
    const id = principal[1] ?? "";
    if (!account.servicePrincipals.some((p) => p.id === id)) {
      return NOT_FOUND();
    }
    account.servicePrincipals = account.servicePrincipals.filter(
      (p) => p.id !== id
    );
    account.assignments = account.assignments.filter(
      (a) => String(a.principal.principal_id) !== id
    );
    delete account.policies[id];
    delete account.entitlements[id];
    return jsonResponse(undefined, { status: 204 });
  }
  if (method === "PATCH" && principal) {
    const found = account.servicePrincipals.find((p) => p.id === principal[1]);
    if (!found) return NOT_FOUND();
    const { Operations } = JSON.parse(body ?? "{}") as {
      Operations: { op: string; path: string; value: { value: string }[] }[];
    };
    for (const { op, path: attribute, value } of Operations) {
      if (op === "replace" && attribute === "active") {
        found.active = value[0]?.value === "true";
      }
    }
    return jsonResponse(undefined, { status: 204 });
  }

  const policies = path.match(
    /^\/servicePrincipals\/(\d+)\/federationPolicies(?:\/([^/]+))?$/
  );
  if (policies) {
    const [, id = "", policyId] = policies;
    if (!account.servicePrincipals.some((p) => p.id === id)) {
      return NOT_FOUND();
    }
    const held = account.policies[id] ?? [];
    if (method === "GET" && !policyId) {
      return jsonResponse({
        policies: held.map((policy) => ({
          ...policy,
          name: `accounts/${ACCOUNT_ID}/servicePrincipals/${id}/federationPolicies/${policy.policy_id}`,
        })),
      });
    }
    if (method === "POST" && !policyId) {
      const newId = query.get("policy_id") ?? "generated";
      if (held.some((p) => p.policy_id === newId)) {
        return error(409, "ALREADY_EXISTS");
      }
      const { oidc_policy } = JSON.parse(body ?? "{}") as {
        oidc_policy: unknown;
      };
      account.policies[id] = [...held, { policy_id: newId, oidc_policy }];
      return jsonResponse({ policy_id: newId, oidc_policy });
    }
    if (method === "DELETE" && policyId) {
      if (!held.some((p) => p.policy_id === policyId)) return NOT_FOUND();
      account.policies[id] = held.filter((p) => p.policy_id !== policyId);
      return jsonResponse({});
    }
  }
  return NOT_FOUND();
};

/** The workspace SCIM ID of a principal, which the fake makes differ from its account SCIM ID. */
export const workspaceScimId = (accountScimId: string) => `9${accountScimId}`;

const WORKSPACE_PRINCIPALS = "/api/2.0/preview/scim/v2/ServicePrincipals";

/**
 * The workspace's own SCIM, which lists the service principals assigned to
 * `WORKSPACE_ID` and their direct entitlements.
 */
const answerWorkspaceScim = (
  account: FakeAccount,
  method: string,
  path: string,
  query: URLSearchParams,
  body: string | undefined
) => {
  const assigned = account.servicePrincipals.filter((p) =>
    account.assignments.some((a) => String(a.principal.principal_id) === p.id)
  );
  const view = (p: Principal) => ({
    id: workspaceScimId(p.id),
    applicationId: p.applicationId,
    displayName: p.displayName,
    entitlements: (account.entitlements[p.id] ?? []).map((value) => ({
      value,
    })),
  });
  if (method === "GET" && path === WORKSPACE_PRINCIPALS) {
    const applicationId = filterValue(query.get("filter"), "applicationId");
    return jsonResponse({
      Resources: assigned
        .filter((p) => same(p.applicationId, applicationId))
        .map(view),
    });
  }
  const one = path.match(
    /^\/api\/2\.0\/preview\/scim\/v2\/ServicePrincipals\/(\d+)$/
  );
  const found = assigned.find((p) => one && workspaceScimId(p.id) === one[1]);
  if (!found) return NOT_FOUND();
  if (method === "GET") return jsonResponse(view(found));
  if (method === "PATCH") {
    const { Operations } = JSON.parse(body ?? "{}") as {
      Operations: { op: string; path: string; value: { value: string }[] }[];
    };
    for (const { op, path: attribute, value } of Operations) {
      if (attribute !== "entitlements") continue;
      const held = new Set(account.entitlements[found.id] ?? []);
      for (const { value: entitlement } of value) {
        if (op === "add") held.add(entitlement);
        if (op === "remove") held.delete(entitlement);
      }
      account.entitlements[found.id] = [...held];
    }
    return jsonResponse(view(found));
  }
  return NOT_FOUND();
};

/** The key the fake files a securable's grants under. */
export const grantsKey = (type: string, fullName: string) =>
  `${type}:${fullName.toLowerCase()}`;

const sameName = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Whether a securable exists. */
const securableExists = (account: FakeAccount, type: string, name: string) => {
  const [catalog = "", schema = "", object = ""] = name.split(".");
  const { uc } = account;
  if (type === "catalog") return uc.catalogs.some((c) => sameName(c, catalog));
  if (type === "schema") {
    return uc.schemas.some(
      (s) => sameName(s.catalog, catalog) && sameName(s.name, schema)
    );
  }
  const kind = `${type}s`;
  return uc.objects.some(
    (o) =>
      o.kind === kind &&
      sameName(o.catalog, catalog) &&
      sameName(o.schema, schema) &&
      sameName(o.name, object)
  );
};

const fullNameOf = (o: FakeAccount["uc"]["objects"][number]) =>
  `${o.catalog}.${o.schema}.${o.name}`;

/**
 * The workspace's SQL warehouses and permissions APIs, and Unity Catalog's
 * permissions, list, get and update APIs, over `account`.
 */
const answerWorkspaceData = (
  account: FakeAccount,
  method: string,
  path: string,
  query: URLSearchParams,
  body: string | undefined
) => {
  if (method === "GET" && path === "/api/2.0/sql/warehouses") {
    return jsonResponse({ warehouses: account.warehouses });
  }
  const warehouse = path.match(/^\/api\/2\.0\/permissions\/warehouses\/(\w+)$/);
  if (warehouse) {
    const id = warehouse[1] ?? "";
    if (!account.warehouses.some((w) => w.id === id)) return NOT_FOUND();
    const acl = account.warehouseAcl[id] ?? [];
    if (method === "PATCH") {
      const { access_control_list } = JSON.parse(body ?? "{}") as {
        access_control_list: {
          service_principal_name: string;
          permission_level: string;
        }[];
      };
      account.warehouseAcl[id] = [
        ...acl.filter(
          (entry) =>
            !access_control_list.some(
              (change) =>
                change.service_principal_name === entry.service_principal_name
            )
        ),
        ...access_control_list,
      ];
    }
    return jsonResponse({
      access_control_list: (account.warehouseAcl[id] ?? []).map(
        ({ service_principal_name, permission_level }) => ({
          service_principal_name,
          all_permissions: [{ permission_level, inherited: false }],
        })
      ),
    });
  }

  const permissions = path.match(
    /^\/api\/2\.1\/unity-catalog\/permissions\/(\w+)\/([^/]+)$/
  );
  if (permissions) {
    const [, type = "", encoded = ""] = permissions;
    const name = decodeURIComponent(encoded);
    if (!securableExists(account, type, name)) {
      return error(404, `${type.toUpperCase()}_DOES_NOT_EXIST`);
    }
    const key = grantsKey(type, name);
    const held = account.grants[key] ?? {};
    const known = (principal: string) =>
      account.servicePrincipals.some((p) =>
        sameName(p.applicationId, principal)
      );
    if (method === "GET") {
      const principal = query.get("principal") ?? "";
      if (!known(principal)) return error(400, "PRINCIPAL_DOES_NOT_EXIST");
      const privileges = held[principal.toLowerCase()] ?? [];
      return jsonResponse({
        privilege_assignments: privileges.length
          ? [{ principal, privileges }]
          : [],
      });
    }
    if (method === "PATCH") {
      const { changes } = JSON.parse(body ?? "{}") as {
        changes: { principal: string; add?: string[]; remove?: string[] }[];
      };
      for (const { principal, add = [], remove = [] } of changes) {
        if (!known(principal)) return error(400, "PRINCIPAL_DOES_NOT_EXIST");
        const set = new Set(held[principal.toLowerCase()] ?? []);
        for (const privilege of add) set.add(privilege);
        for (const privilege of remove) set.delete(privilege);
        held[principal.toLowerCase()] = [...set];
      }
      account.grants[key] = held;
      return jsonResponse({});
    }
  }

  const list = path.match(
    /^\/api\/2\.1\/unity-catalog\/(catalogs|schemas|tables|volumes|functions)$/
  );
  if (method === "GET" && list) {
    const kind = list[1] ?? "";
    const catalog = query.get("catalog_name") ?? "";
    const schema = query.get("schema_name") ?? "";
    const { uc } = account;
    if (kind === "catalogs") {
      return jsonResponse({ catalogs: uc.catalogs.map((name) => ({ name })) });
    }
    if (!uc.catalogs.some((c) => sameName(c, catalog))) {
      return error(404, "CATALOG_DOES_NOT_EXIST");
    }
    if (kind === "schemas") {
      return jsonResponse({
        schemas: uc.schemas
          .filter((s) => sameName(s.catalog, catalog))
          .map(({ name }) => ({ name, full_name: `${catalog}.${name}` })),
      });
    }
    if (!securableExists(account, "schema", `${catalog}.${schema}`)) {
      return error(404, "SCHEMA_DOES_NOT_EXIST");
    }
    return jsonResponse({
      [kind]: uc.objects
        .filter(
          (o) =>
            o.kind === kind &&
            sameName(o.catalog, catalog) &&
            sameName(o.schema, schema)
        )
        .map((o) => ({
          name: o.name,
          full_name: fullNameOf(o),
          owner: o.owner,
        })),
    });
  }

  const object = path.match(
    /^\/api\/2\.1\/unity-catalog\/(tables|volumes|functions)\/([^/]+)$/
  );
  if (object) {
    const [, kind = "", encoded = ""] = object;
    const name = decodeURIComponent(encoded);
    const found = account.uc.objects.find(
      (o) => o.kind === kind && sameName(fullNameOf(o), name)
    );
    if (!found) {
      return error(404, `${kind.slice(0, -1).toUpperCase()}_DOES_NOT_EXIST`);
    }
    if (method === "PATCH") {
      const { owner } = JSON.parse(body ?? "{}") as { owner: string };
      found.owner = owner;
    }
    return jsonResponse({
      name: found.name,
      full_name: fullNameOf(found),
      owner: found.owner,
    });
  }
  return NOT_FOUND();
};

const failure = (failed: Failure) =>
  typeof failed === "number"
    ? error(failed, failed >= 500 ? "INTERNAL_ERROR" : "BAD_REQUEST")
    : error(failed.status, failed.errorCode);

/**
 * Answers the connector the way Databricks would for `account`: the account
 * APIs on the account console, and the Databricks SQL MCP server and the
 * workspace SCIM on any workspace origin. A call named in `account.fail`
 * fails first. Anything else is a 404.
 */
export const databricks =
  (account: FakeAccount) =>
  (url: string, init: RequestInit): FakeResponse => {
    const { origin, pathname, searchParams } = new URL(url);
    const method = init.method ?? "GET";
    const failed = account.fail[`${method} ${pathname}`];
    if (failed !== undefined) return failure(failed);
    if (pathname === DBSQL_MCP_PATH && origin !== ACCOUNTS_URL) {
      return answerMcp(account, init);
    }
    if (pathname.startsWith(WORKSPACE_PRINCIPALS) && origin !== ACCOUNTS_URL) {
      return answerWorkspaceScim(
        account,
        method,
        pathname,
        searchParams,
        init.body as string | undefined
      );
    }
    if (origin !== ACCOUNTS_URL) {
      return answerWorkspaceData(
        account,
        method,
        pathname,
        searchParams,
        init.body as string | undefined
      );
    }
    const prefix = `/api/2.0/accounts/${ACCOUNT_ID}`;
    if (origin !== ACCOUNTS_URL || !pathname.startsWith(prefix)) {
      return NOT_FOUND();
    }
    return answerAccount(
      account,
      method,
      pathname.slice(prefix.length),
      searchParams,
      init.body as string | undefined
    );
  };
