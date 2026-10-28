import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import {
  type DatabricksRequest,
  databricksRequest,
  databricksStatus,
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

/**
 * Whether account SCIM `roles` include {@link ACCOUNT_ADMIN_ROLE}.
 *
 * The INT-810 live check saw account SCIM list `account_admin` in a service
 * principal's `roles`. Databricks (HI) reads it the same way.
 */
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
    message: `Service principal ${applicationId} is not an account admin in Databricks account ${accountId}. Check that the account's Terraform, which gives it that role, is applied.`,
    payload: { requestId, applicationId },
    cause,
  });

/**
 * Runs an account API call that needs account admin. The account APIs refuse
 * any other principal with a 403, which becomes {@link notAccountAdmin}.
 */
export const asAccountAdmin = async <T>(
  context: DatabricksAccountContext,
  call: () => Promise<T>
): Promise<T> =>
  await withForbiddenAs((cause) => notAccountAdmin(context, cause), call);

/** One Databricks REST call, relative to the account or workspace it targets. */
type DatabricksCall = Pick<DatabricksRequest, "method" | "path" | "query"> & {
  /** Serialized as the JSON request body. */
  body?: unknown;
  /** The `Accept` header. `application/json` unless set. */
  accept?: string;
  /** More request headers. They can't replace `Authorization` or `Accept`. */
  headers?: Record<string, string>;
};

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

  const request = async (
    origin: string,
    call: DatabricksCall
  ): Promise<DatabricksRequest> => {
    const { body, accept, headers, ...rest } = call;
    const token = await databricksAccessToken(context);
    return {
      ...rest,
      origin,
      requestId,
      headers: {
        ...headers,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        Accept: accept ?? "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    };
  };

  /** Calls an account API. `path` is relative to `/api/2.0/accounts/<accountId>`. */
  const account = async (call: DatabricksCall) =>
    await databricksRequest(
      await request(accountsUrl, {
        ...call,
        path: `/api/2.0/accounts/${encodeURIComponent(accountId)}${call.path}`,
      })
    );

  /**
   * The workspace origin `url` names, re-parsed here so a token can never go
   * to a host that isn't Databricks, even if a caller skipped a parser.
   */
  const workspaceOrigin = (url: string) => {
    const origin = workspaceUrl.safeParse(url);
    if (!origin.success) {
      throw new ConnectorError({
        type: "validation_error",
        message: "Workspace URL must be https://<host> on a Databricks domain.",
        payload: { requestId },
      });
    }
    return origin.data;
  };

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
   * account and principal for the life of the Lambda instance. The
   * application ID comes from the request context, but it is also the
   * principal the token was issued to: the token cache is keyed on it, and
   * the exchange fails for any principal whose federation policy doesn't
   * trust the connector's role.
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
    /** Calls a workspace API and returns its JSON body. `path` is the full API path. */
    call: async (call: DatabricksCall) =>
      await databricksRequest(await request(workspaceOrigin(url), call)),
    /**
     * Calls a workspace API and returns only its status and response
     * headers, whatever the status. `path` is the full API path.
     */
    status: async (call: DatabricksCall) =>
      await databricksStatus(await request(workspaceOrigin(url), call)),
  });

  return { context, account, inWorkspace, ownServicePrincipal };
};

export type DatabricksClient = ReturnType<typeof newDatabricksClient>;

/** A {@link DatabricksClient} bound to one workspace. */
export type DatabricksWorkspaceClient = ReturnType<
  DatabricksClient["inWorkspace"]
>;

/**
 * Refuses a grantee that is the connector's own service principal, the one
 * {@link DatabricksClient.ownServicePrincipal} returns.
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
      message:
        "P0 cannot grant access to its own Databricks service principal.",
      payload: { requestId },
    });
  }
};
