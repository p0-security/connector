import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import {
  type DatabricksRequest,
  databricksRequest,
  memoizeByKey,
  parse,
  withForbiddenAs,
} from "./api.ts";
import {
  type DatabricksAccountContext,
  cacheKey,
  workspaceUrl,
} from "./context.ts";
import { databricksAccessToken } from "./federation.ts";

/** The account SCIM `roles` value that makes a user or service principal an account admin. */
export const ACCOUNT_ADMIN_ROLE = "account_admin";

/** The `roles` of a user or service principal in account SCIM. */
export const scimRoles = z.object({
  roles: z.array(z.object({ value: z.string() })).optional(),
});

/** Whether account SCIM `roles` include {@link ACCOUNT_ADMIN_ROLE}. */
export const hasAccountAdmin = ({ roles }: z.infer<typeof scimRoles>) =>
  roles?.some(({ value }) => value === ACCOUNT_ADMIN_ROLE) ?? false;

/**
 * The refusal for a service principal that isn't an account admin, whether
 * its `roles` lack {@link ACCOUNT_ADMIN_ROLE} or account SCIM refuses it
 * outright with a 403.
 */
export const notAccountAdmin = (
  { requestId, accountId, applicationId }: DatabricksAccountContext,
  cause?: unknown
) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `Service principal ${applicationId} is not an account admin in Databricks account ${accountId}`,
    payload: { requestId, applicationId },
    cause,
  });

/**
 * Runs an account SCIM call that needs account admin. Account SCIM refuses
 * any other principal with a 403, which becomes {@link notAccountAdmin}.
 */
export const asAccountAdmin = async <T>(
  context: DatabricksAccountContext,
  call: () => Promise<T>
): Promise<T> =>
  await withForbiddenAs((cause) => notAccountAdmin(context, cause), call);

/** The system group whose members are a workspace's admins. */
export const WORKSPACE_ADMINS_GROUP = "admins";

/** One Databricks REST call, relative to the account or workspace it targets. */
type DatabricksCall = Pick<DatabricksRequest, "method" | "path" | "query"> & {
  /** Serialized as the JSON request body. */
  body?: unknown;
};

const ownIdentityResponse = z.object({
  id: z.string().min(1),
  userName: z.string().optional(),
  displayName: z.string().optional(),
  /** The workspace groups the principal is in, which show whether it is an admin. */
  groups: z
    .array(z.object({ display: z.string().optional(), value: z.string() }))
    .optional(),
});

/**
 * The connector's own principal, as Databricks reports it from `SCIM /Me` on
 * the federated token. For a service principal `userName` is its
 * `application_id`.
 */
export type OwnIdentity = z.infer<typeof ownIdentityResponse>;

/**
 * Whether `SCIM /Me` lists the workspace's {@link WORKSPACE_ADMINS_GROUP},
 * which is what makes a principal a workspace admin.
 */
export const isWorkspaceAdmin = ({ groups }: OwnIdentity) =>
  groups?.some(({ display }) => display === WORKSPACE_ADMINS_GROUP) ?? false;

const servicePrincipalList = z.object({
  Resources: z
    .array(
      z.object({
        id: z.string().min(1),
        applicationId: z.string(),
        displayName: z.string().optional(),
      })
    )
    .optional(),
});

/** The connector's own service principal, as account SCIM reports it. */
export type OwnServicePrincipal = {
  id: string;
  applicationId: string;
  displayName?: string;
};

/**
 * The connector's service principal per account and application ID. A
 * principal's SCIM ID never changes, so each is looked up once for the life of
 * the Lambda instance. A failed lookup is not cached.
 */
const ownServicePrincipals = new Map<string, Promise<OwnServicePrincipal>>();

/** Clears every cached service principal. For tests. */
export const resetOwnServicePrincipalCache = () => ownServicePrincipals.clear();

/**
 * A Databricks client for one request, acting as the service principal the
 * request context names. Every call authenticates with a federated token (see
 * {@link databricksAccessToken}) and carries the connector's `User-Agent`.
 */
export const newDatabricksClient = (context: DatabricksAccountContext) => {
  const { accountsUrl, accountId, requestId } = context;

  const call = async (origin: string, request: DatabricksCall) => {
    const { body, ...rest } = request;
    const token = await databricksAccessToken(context);
    return await databricksRequest({
      ...rest,
      origin,
      requestId,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  };

  /** Calls an account API. `path` is relative to `/api/2.0/accounts/<accountId>`. */
  const account = async (request: DatabricksCall) =>
    await call(accountsUrl, {
      ...request,
      path: `/api/2.0/accounts/${encodeURIComponent(accountId)}${request.path}`,
    });

  /** Calls a workspace API. `path` is the full API path, e.g. `/api/2.1/unity-catalog/catalogs`. */
  const workspace = async (url: string, request: DatabricksCall) => {
    // Re-parsed here so a token can never go to a host that isn't Databricks,
    // even if a caller skipped the request-context parser.
    const origin = workspaceUrl.safeParse(url);
    if (!origin.success) {
      throw new ConnectorError({
        type: "validation_error",
        message: "Workspace URL must be https://<host> on a Databricks domain",
        payload: { requestId },
      });
    }
    return await call(origin.data, request);
  };

  /**
   * The connector's own identity in a workspace, from `SCIM /Me` on its
   * federated token. A call that succeeds proves the principal is assigned to
   * the workspace.
   */
  const ownIdentity = async (url: string): Promise<OwnIdentity> =>
    parse({
      schema: ownIdentityResponse,
      data: await workspace(url, {
        method: "GET",
        path: "/api/2.0/preview/scim/v2/Me",
      }),
      what: "SCIM /Me",
      requestId,
    });

  const readOwnServicePrincipal = async (): Promise<OwnServicePrincipal> => {
    const { applicationId } = context;
    const { Resources = [] } = parse({
      schema: servicePrincipalList,
      data: await asAccountAdmin(context, async () =>
        account({
          method: "GET",
          path: "/scim/v2/ServicePrincipals",
          query: { filter: `applicationId eq "${applicationId}"` },
        })
      ),
      what: "account SCIM ServicePrincipals",
      requestId,
    });
    // Re-checked, so a server that ignored the filter can't hand back another
    // principal.
    const own = Resources.find(
      (principal) => principal.applicationId === applicationId
    );
    if (!own) {
      throw new ConnectorError({
        type: "object_not_found",
        message: `No service principal with application ID ${applicationId} in Databricks account ${accountId}`,
        payload: { requestId, query: applicationId },
      });
    }
    const { id, displayName } = own;
    return { id, applicationId, ...(displayName ? { displayName } : {}) };
  };

  /**
   * The connector's own service principal in account SCIM, found by the
   * `application_id` its token was exchanged for, and looked up once per
   * account and principal for the life of the Lambda instance. It needs no
   * workspace, unlike `SCIM /Me`, which is a workspace API. The application
   * ID comes from the request context, but it is also the principal the token
   * was issued to: the token cache is keyed on it, and the exchange fails for
   * any principal whose federation policy doesn't trust the connector's role.
   */
  const ownServicePrincipal = async (): Promise<OwnServicePrincipal> =>
    await memoizeByKey(
      ownServicePrincipals,
      cacheKey(context),
      readOwnServicePrincipal
    );

  /**
   * The same client bound to one workspace, for code that only ever calls
   * that workspace. `url` must be the workspace's origin, which is re-checked
   * on every call.
   */
  const inWorkspace = (url: string) => ({
    requestId,
    /** Calls a workspace API. `path` is the full API path. */
    call: async (request: DatabricksCall) => await workspace(url, request),
    /** The connector's own identity in this workspace, from `SCIM /Me`. */
    ownIdentity: async () => await ownIdentity(url),
  });

  return { context, account, inWorkspace, ownServicePrincipal };
};

export type DatabricksClient = ReturnType<typeof newDatabricksClient>;

/** A {@link DatabricksClient} bound to one workspace. */
export type DatabricksWorkspaceClient = ReturnType<
  DatabricksClient["inWorkspace"]
>;

/**
 * Refuses a grantee that is the connector's own service principal: the one
 * {@link DatabricksClient.ownServicePrincipal} returns, or in a workspace the
 * one `SCIM /Me` returns. `admin` only ever acts on users that account SCIM
 * `Users` returns, which never include a service principal, so this is
 * defence in depth.
 *
 * It matches by account SCIM ID, which can't miss: users and service
 * principals share one ID space in an account, which is why the workspace
 * assignment API takes either as a `principal_id`.
 */
export const assertNotOwnPrincipal = (
  own: { id: string },
  grantee: { id: string },
  requestId: string
) => {
  if (grantee.id === own.id) {
    throw new ConnectorError({
      type: "validation_error",
      message: "P0 cannot grant access to its own Databricks service principal",
      payload: { requestId },
    });
  }
};
