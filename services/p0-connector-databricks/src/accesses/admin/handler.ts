import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector";

import { memoizeByKey } from "../../databricks/api.ts";
import {
  assertNotOwnPrincipal,
  hasAccountAdmin,
  newDatabricksClient,
} from "../../databricks/client.ts";
import {
  type DatabricksAccountContext,
  cacheKey,
} from "../../databricks/context.ts";
import type { ScimUser } from "../../databricks/scim-users.ts";
import {
  WORKSPACE_PAIR_ERROR,
  inBoundWorkspace,
} from "../../databricks/workspaces.ts";
import { verifyEmailDomain } from "../../domain.ts";
import { neverDeleteUser, userMustAlreadyExist } from "../common/handler.ts";
import {
  type AccountAdminApi,
  type WorkspaceAdminApi,
  type WorkspaceAssignment,
  newAccountAdminApi,
  newWorkspaceAdminApi,
} from "./api.ts";
import { spec } from "./definition.ts";

type AdminSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = AdminSchema["RequestContext"];

const WORKSPACE_ASSIGNMENT_LABELS: Record<WorkspaceAssignment, string> = {
  none: "Not assigned to the workspace",
  USER: "Workspace user",
  ADMIN: "Workspace admin",
};

/** What a context or lister query names: the account, and maybe a workspace. */
type ScopeRef = DatabricksAccountContext & {
  workspaceId?: string;
  workspaceUrl?: string;
};

/**
 * Which scope a context or query names: the workspace when it carries
 * either half of the workspace pair, and the account otherwise. The parsers
 * refuse half a pair, and so does this, so a context with only a workspace
 * ID can never fall through to the account scope.
 */
export const adminScopeOf = ({
  requestId,
  workspaceId,
  workspaceUrl,
}: ScopeRef):
  | { kind: "account" }
  | { kind: "workspace"; workspaceId: string; workspaceUrl: string } => {
  if (workspaceId === undefined && workspaceUrl === undefined) {
    return { kind: "account" };
  }
  if (workspaceId === undefined || workspaceUrl === undefined) {
    throw new ConnectorError({
      type: "validation_error",
      message: WORKSPACE_PAIR_ERROR,
      payload: { requestId },
    });
  }
  return { kind: "workspace", workspaceId, workspaceUrl };
};

/** The APIs one call acts through, and the principal it must never act on. */
type Scope =
  | {
      kind: "account";
      api: AccountAdminApi;
      ownPrincipal: () => Promise<{ id: string }>;
    }
  | {
      kind: "workspace";
      workspaceId: string;
      api: WorkspaceAdminApi;
      ownPrincipal: () => Promise<{ id: string }>;
    };

/**
 * Opens the scope a context or query names. The account scope uses account
 * SCIM and its own principal from account SCIM. The workspace scope binds the
 * workspace first, then uses its SCIM proxy, its assignment API and its
 * `SCIM /Me`.
 *
 * A revoke that can't bind its workspace fails saying so, keeping the
 * binding error's type. It never counts as revoked: a workspace that only
 * answers wrongly may still hold the role.
 */
const openScope = async (
  ref: ScopeRef,
  { isRevoke }: { isRevoke: boolean }
): Promise<Scope> => {
  const client = newDatabricksClient(ref);
  const scope = adminScopeOf(ref);
  if (scope.kind === "account") {
    return {
      kind: "account",
      api: newAccountAdminApi(client),
      ownPrincipal: client.ownServicePrincipal,
    };
  }
  const { workspaceId, workspaceUrl } = scope;
  let workspace;
  try {
    workspace = await inBoundWorkspace(client, scope);
  } catch (error) {
    if (!isRevoke) throw error;
    throw new ConnectorError({
      type: error instanceof ConnectorError ? error.data.type : "unknown",
      message: `P0 can't reach Databricks workspace ${workspaceId} at ${workspaceUrl} to revoke workspace admin. If the workspace was deleted, the user's admin role went with it.`,
      payload: { requestId: ref.requestId, workspaceId, workspaceUrl },
      cause: error,
    });
  }
  return {
    kind: "workspace",
    workspaceId,
    api: newWorkspaceAdminApi(workspace, workspaceId),
    ownPrincipal: workspace.ownIdentity,
  };
};

const verificationFailed = (
  context: RequestContext,
  user: ScimUser,
  message: string
) =>
  new ConnectorError({
    type: "unknown",
    message,
    payload: { requestId: context.requestId, userId: user.id },
  });

/** What a grant or revoke acts on: one user, through one scope's API. */
type Change<Api> = {
  api: Api;
  logger: Logger;
  context: RequestContext;
  user: ScimUser;
  /** Whether to grant the role; `false` revokes it. */
  grant: boolean;
};

/**
 * Grants workspace admin, or on revoke restores the user's prior assignment.
 *
 * A grant refuses if the user's assignment is neither what it was when the
 * request was approved (`priorAssignment`) nor already `ADMIN`, since revoke
 * would later restore a state someone has since changed.
 *
 * A revoke only ever lowers access. It acts only while the user is `ADMIN`,
 * and then restores `priorAssignment`, which is `none` (the assignment is
 * deleted) or `USER`, both below `ADMIN`. If someone already demoted or
 * removed the user, P0 leaves their current state alone, so a revoke never
 * creates or raises an assignment.
 */
const setWorkspaceAdmin = async ({
  api,
  logger,
  context,
  user,
  grant,
  workspaceId,
}: Change<WorkspaceAdminApi> & { workspaceId: string }) => {
  const { priorAssignment, requestId } = context;
  const current = await api.workspaceAssignment(user);

  if ((current === "ADMIN") === grant) {
    logger.info(
      { current },
      grant
        ? "user is already workspace admin; nothing to grant"
        : "user is no longer workspace admin; nothing to revoke"
    );
    return;
  }
  if (grant && current !== priorAssignment) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The user's workspace assignment changed since the request was approved (it was ${priorAssignment}, it is now ${current}). Resubmit the request.`,
      payload: { requestId, userId: user.id, workspaceId },
    });
  }

  const target: WorkspaceAssignment = grant ? "ADMIN" : priorAssignment;
  if (target === "none") {
    await api.deleteWorkspaceAssignment(user.id);
  } else {
    await api.putWorkspaceAssignment({ userId: user.id, permission: target });
  }

  const after = await api.workspaceAssignment(user);
  if (after !== target) {
    throw verificationFailed(
      context,
      user,
      `Databricks reports user ${user.id} as ${after} on workspace ${workspaceId} after P0 set ${target}`
    );
  }
  logger.info({ from: current, to: target }, "set workspace assignment");
};

/**
 * Adds or removes `account_admin` on the user's account SCIM `roles`. A revoke
 * only ever removes the role, and does nothing if it's already gone.
 */
const setAccountAdmin = async ({
  api,
  logger,
  context,
  user,
  grant,
}: Change<AccountAdminApi>) => {
  if (hasAccountAdmin(user) === grant) {
    logger.info(
      grant
        ? "user is already account admin; nothing to grant"
        : "user is no longer account admin; nothing to revoke"
    );
    return;
  }

  if (grant) await api.addAccountAdmin(user.id);
  else await api.removeAccountAdmin(user.id);

  const after = await api.readUser(user.id);
  if (!after || hasAccountAdmin(after) !== grant) {
    throw verificationFailed(
      context,
      user,
      `Databricks still reports user ${user.id} ${grant ? "without" : "with"} account admin after P0 ${grant ? "added" : "removed"} it`
    );
  }
  logger.info({ grant }, "set account admin");
};

/**
 * Workspace admin, through the workspace's own permission assignment API and
 * its proxy of account SCIM, and account admin, through the account SCIM
 * user's `roles` (resource root). P0 never puts a user in a group to do
 * either. Workspace admin needs P0's principal to be an admin of the
 * workspace, and account admin needs it to be an account admin. A call in
 * either scope that Databricks refuses says which.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<AdminSchema>(t, spec, (ctx: ConnectorContext) => {
    // The primitives are built once per call, so the grantee read the
    // validation hook makes is reused by `setPoliciesForUser`.
    const grantees = new Map<string, Promise<ScimUser>>();

    /**
     * Reads the grantee by account SCIM ID in the context's scope, refusing
     * it unless it is a user. Account SCIM `Users`, and the workspace's proxy
     * of it, only know users, so a service principal's or group's ID is
     * refused here.
     */
    const readGrantee = async (
      context: RequestContext,
      userId: string,
      isRevoke: boolean
    ) =>
      await memoizeByKey(
        grantees,
        `${cacheKey(context)}|${context.workspaceUrl ?? "account"}|${userId}`,
        async () => {
          const { api } = await openScope(context, { isRevoke });
          const user = await api.readUser(userId);
          if (!user) {
            throw new ConnectorError({
              type: "validation_error",
              message: `P0 grants Databricks admin roles only to users, and ${userId} is not a user in this account`,
              payload: { requestId: context.requestId, userId },
            });
          }
          return user;
        }
      );

    return {
      // The framework runs these before every operation that names a user.
      // Each throws a refusal that says why, rather than returning false.
      validation: (context) => ({
        user: {
          // Domain verification gates a user resolved from an email. A body
          // carrying the `userId` P0 recorded at stage names a user P0
          // already verified, so that lookup checks nothing and logs
          // nothing: a lookup never changes access, and
          // `setPoliciesForUser` makes the decision. The framework also runs
          // this before `deleteUser` and `setPoliciesForUser`, and a revoke
          // is never refused: it only warns, as `setPoliciesForUser` does.
          // Like the ID check below, it takes the call for a revoke by its
          // `operation` alone.
          userIsNamespacedByBody: async ({ email, userId }) => {
            if (!userId) {
              verifyEmailDomain({
                email,
                requestId: context.requestId,
                alreadyGranted: context.operation === "revoke",
              });
            }
            return true;
          },
          // Users only. Domain verification for an ID runs once, in
          // `setPoliciesForUser`. This runs before `setPoliciesForUser`
          // sees the policies, so it takes the call for a revoke by its
          // `operation` alone.
          userIsNamespacedById: async (userId) => {
            await readGrantee(context, userId, context.operation === "revoke");
            return true;
          },
        },
      }),

      /**
       * Reads the user by the account SCIM ID P0 recorded at stage, when
       * there is one, and otherwise finds them by the requestor's email, in
       * which case their `userName` must pass domain verification. Either
       * read goes through the context's scope. A user who no longer exists
       * is `null`, which on revoke means there is nothing left to revoke.
       *
       * Neither this nor `validation` reads `operation` to decide anything
       * but how to report a workspace it can't bind, and whether a domain
       * mismatch refuses the call or only warns. A lookup that rolls
       * back a failed grant says `"grant"`, but it carries the recorded
       * `userId` like a revoke's, so domain verification never refuses it.
       */
      getUser: async (context, { email, userId }) => {
        const { api } = await openScope(context, {
          isRevoke: context.operation === "revoke",
        });
        if (userId) return (await api.readUser(userId))?.id ?? null;
        const user = await api.users.byEmail(email);
        if (!user) return null;
        verifyEmailDomain({
          email: user.userName,
          requestId: context.requestId,
          alreadyGranted: false,
        });
        return user.id;
      },

      createUser: userMustAlreadyExist,

      deleteUser: neverDeleteUser,

      /**
       * Grants the scope's role, or revokes it. A call is a revoke when the
       * context's `operation` says so or when it carries no policy, and a
       * grant otherwise. A revoke only ever lowers access. The control plane
       * sets `operation` from the request's status, so the calls that roll
       * back a grant that failed partway say `"grant"`, but they carry no
       * policy unless another open request on the scope still holds the
       * role. Only a rollback should say `"grant"` and carry no policy, so
       * taking a call for a revoke against its label logs a warning.
       *
       * On a revoke the policy is still there while another open request on
       * the scope holds the role, and then nothing changes. A workspace
       * admin revoke that can't bind its workspace fails, and never counts
       * as revoked. A rollback fails with the binding's own error instead of
       * the revoke message, because the validation hook binds first, before
       * the policies say the call is a revoke.
       */
      setPoliciesForUser: async (context, userId, _user, policies) => {
        const { requestId, accountId, workspaceId, operation } = context;
        const effectiveOperation: RequestContext["operation"] =
          operation === "revoke" || policies.length === 0 ? "revoke" : "grant";
        const grant = effectiveOperation === "grant";
        const log = ctx.logger.child({
          requestId,
          accountId,
          workspaceId,
          userId,
          operation,
          effectiveOperation,
        });
        if (effectiveOperation !== operation) {
          // A control-plane bug that sent a grant without its role would look
          // just like this, so it is never silent.
          log.warn(
            "call says grant but carries no policy; treating it as the rollback of a failed grant"
          );
        }

        // The resource is the workspace when one is named and the account
        // otherwise. Any other policy is a control-plane bug, not a user error.
        const resourcePolicy =
          adminScopeOf(context).kind === "workspace"
            ? "WORKSPACE_ADMIN"
            : "ACCOUNT_ADMIN";
        const unexpected = policies.filter(
          (policy) => policy !== resourcePolicy
        );
        if (unexpected.length > 0) {
          throw new ConnectorError({
            type: "unknown",
            message: `Expected only ${resourcePolicy} ${workspaceId ? `for workspace ${workspaceId}` : "without a workspace"}, got ${unexpected.join(", ")}`,
            payload: { requestId, userId },
          });
        }

        const scope = await openScope(context, { isRevoke: !grant });
        const user = await readGrantee(context, userId, !grant);
        // Domain verification on the `userName`. A grant to a user who fails
        // is refused before anything is written, even if they already hold
        // the role. A revoke is never refused: it warns, and only ever lowers
        // access (see `setWorkspaceAdmin` and `setAccountAdmin`).
        verifyEmailDomain({
          email: user.userName,
          requestId,
          alreadyGranted: !grant,
        });
        // Defence in depth: `readGrantee` only ever returns a user, and
        // account SCIM `Users` never returns a service principal. Checked
        // before the revoke below that changes nothing, so it holds on
        // every call. In a workspace, the principal is `SCIM /Me` there.
        assertNotOwnPrincipal(await scope.ownPrincipal(), user, requestId);
        if (!grant && policies.length > 0) {
          log.info(
            "another open request still holds the role; nothing to revoke"
          );
          return;
        }

        const change = { logger: log, context, user, grant };
        if (scope.kind === "account") {
          await setAccountAdmin({ ...change, api: scope.api });
        } else {
          await setWorkspaceAdmin({
            ...change,
            api: scope.api,
            workspaceId: scope.workspaceId,
          });
        }
      },

      // `priorAssignment` is the only query.
      list: async ({ context, userId, workspaceId, workspaceUrl }) => {
        const scope = await openScope(
          { ...context, workspaceId, workspaceUrl },
          { isRevoke: false }
        );
        const user = await scope.api.readUser(userId);
        if (!user) {
          throw new ConnectorError({
            type: "object_not_found",
            message: `No Databricks user with ID ${userId}`,
            payload: { requestId: context.requestId, query: userId },
          });
        }
        if (scope.kind === "workspace") {
          const assignment = await scope.api.workspaceAssignment(user);
          return [
            {
              key: assignment,
              value: WORKSPACE_ASSIGNMENT_LABELS[assignment],
            },
          ];
        }
        return hasAccountAdmin(user)
          ? [{ key: "ADMIN", value: "Account admin" }]
          : [{ key: "none", value: "Not an account admin" }];
      },
    };
  });
