import { ConnectorError } from "@p0security/connector-core";
import { z } from "zod";

import { isNotFound, parse, withForbiddenAs } from "../../databricks/api.ts";
import {
  ACCOUNT_ADMIN_ROLE,
  type DatabricksClient,
  type DatabricksWorkspaceClient,
} from "../../databricks/client.ts";
import {
  type ScimUser,
  type ScimUsersEndpoint,
  accountScimUsers,
  newScimUsers,
  workspaceScimUsers,
} from "../../databricks/scim-users.ts";
import type { workspaceAssignment } from "./definition.ts";

const SCIM_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/** The workspace's own permission assignment API. */
const ASSIGNMENTS_PATH = "/api/2.0/preview/permissionassignments";

const permissionAssignmentList = z.object({
  permission_assignments: z
    .array(
      z.object({
        principal: z.object({
          principal_id: z.number().optional(),
          user_name: z.string().optional(),
        }),
        permissions: z.array(z.string()).optional(),
      })
    )
    .optional(),
});

/** A user's own (direct) assignment on a workspace. */
export type WorkspaceAssignment = z.infer<typeof workspaceAssignment>;

/** Runs a call in one scope, turning a 403 into that scope's refusal. */
type ScopeGuard = <T>(call: () => Promise<T>) => Promise<T>;

/** `endpoint`, with every read run through `guard`. */
const guardedEndpoint = (
  endpoint: ScimUsersEndpoint,
  guard: ScopeGuard
): ScimUsersEndpoint => ({
  ...endpoint,
  get: async (path, query) => await guard(() => endpoint.get(path, query)),
});

/**
 * The account-level calls account admin makes, acting as the service
 * principal `client` authenticates as: account SCIM `Users`, and the
 * `account_admin` role on a user's `roles`. None of them touches a group. A
 * 403 from any of them says P0's principal isn't an account admin.
 */
export const newAccountAdminApi = (client: DatabricksClient) => {
  const { requestId, accountId } = client.context;

  const guardAccountScope: ScopeGuard = async (call) =>
    await withForbiddenAs(
      (cause) =>
        new ConnectorError({
          type: "insufficient_privileges",
          message: `P0's service principal isn't an account admin in Databricks account ${accountId}, so P0 can't manage account admin there. Turn on account-admin requests for the account in P0, and apply the Terraform that P0 shows.`,
          payload: { requestId, accountId },
          cause,
        }),
      call
    );

  const users = newScimUsers(
    guardedEndpoint(accountScimUsers(client), guardAccountScope)
  );

  const userPath = (userId: string) =>
    `/scim/v2/Users/${encodeURIComponent(userId)}`;

  const patchRoles = async (userId: string, operation: unknown) =>
    await guardAccountScope(() =>
      client.account({
        method: "PATCH",
        path: userPath(userId),
        body: { schemas: [SCIM_PATCH_OP], Operations: [operation] },
      })
    );

  const addAccountAdmin = async (userId: string) => {
    await patchRoles(userId, {
      op: "add",
      value: { roles: [{ value: ACCOUNT_ADMIN_ROLE }] },
    });
  };

  const removeAccountAdmin = async (userId: string) => {
    await patchRoles(userId, {
      op: "remove",
      path: `roles[value eq "${ACCOUNT_ADMIN_ROLE}"]`,
    });
  };

  return { users, readUser: users.byId, addAccountAdmin, removeAccountAdmin };
};

export type AccountAdminApi = ReturnType<typeof newAccountAdminApi>;

/**
 * The workspace-level calls workspace admin makes in one bound workspace:
 * the workspace's proxy of account SCIM `Users`, and the workspace's own
 * permission assignment API. A user's assignment is the only thing it
 * writes, and none of these calls touches a group. A 403 from any of them
 * says P0's principal isn't an admin of the workspace.
 */
export const newWorkspaceAdminApi = (
  workspace: DatabricksWorkspaceClient,
  workspaceId: string
) => {
  const { requestId } = workspace;

  const guardWorkspaceScope: ScopeGuard = async (call) =>
    await withForbiddenAs(
      (cause) =>
        new ConnectorError({
          type: "insufficient_privileges",
          message: `P0's service principal isn't an admin of Databricks workspace ${workspaceId}, so P0 can't manage workspace admin there. Turn on workspace-admin requests for the workspace in P0, and apply the Terraform that P0 shows.`,
          payload: { requestId, workspaceId },
          cause,
        }),
      call
    );

  const users = newScimUsers(
    guardedEndpoint(workspaceScimUsers(workspace), guardWorkspaceScope)
  );

  const assignmentPath = (userId: string) =>
    `${ASSIGNMENTS_PATH}/principals/${encodeURIComponent(userId)}`;

  /** The user's own assignment on the workspace. */
  const workspaceAssignment = async (
    user: ScimUser
  ): Promise<WorkspaceAssignment> => {
    const response = parse({
      schema: permissionAssignmentList,
      data: await guardWorkspaceScope(() =>
        workspace.call({
          method: "GET",
          path: ASSIGNMENTS_PATH,
        })
      ),
      what: "workspace permission assignments",
      requestId,
    });
    // `principal_id` is an int64 that JSON parsing rounds above 2^53, so it is
    // only compared when it survived parsing exactly. `user_name` identifies
    // the user either way.
    const entry = (response.permission_assignments ?? []).find(
      ({ principal: { principal_id, user_name } }) =>
        (principal_id !== undefined &&
          Number.isSafeInteger(principal_id) &&
          String(principal_id) === user.id) ||
        user_name?.toLowerCase() === user.userName.toLowerCase()
    );
    if (!entry) return "none";
    const permissions = entry.permissions ?? [];
    if (permissions.includes("ADMIN")) return "ADMIN";
    if (permissions.includes("USER")) return "USER";
    throw new ConnectorError({
      type: "unknown",
      message: `Databricks reports unrecognized permissions [${permissions.join(", ")}] for user ${user.id} on workspace ${workspaceId}`,
      payload: { requestId, workspaceId, userId: user.id },
    });
  };

  /** Sets the user's workspace assignment to exactly `permission`. */
  const putWorkspaceAssignment = async ({
    userId,
    permission,
  }: {
    userId: string;
    permission: Exclude<WorkspaceAssignment, "none">;
  }) => {
    await guardWorkspaceScope(() =>
      workspace.call({
        method: "PUT",
        path: assignmentPath(userId),
        body: { permissions: [permission] },
      })
    );
  };

  /** Removes the user's workspace assignment. An assignment that's already gone counts as removed. */
  const deleteWorkspaceAssignment = async (userId: string) => {
    try {
      await guardWorkspaceScope(() =>
        workspace.call({ method: "DELETE", path: assignmentPath(userId) })
      );
    } catch (error) {
      if (!isNotFound(error)) throw error;
    }
  };

  return {
    users,
    readUser: users.byId,
    workspaceAssignment,
    putWorkspaceAssignment,
    deleteWorkspaceAssignment,
  };
};

export type WorkspaceAdminApi = ReturnType<typeof newWorkspaceAdminApi>;
