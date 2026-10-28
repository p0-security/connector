import { z } from "zod";

import { parse } from "./api.ts";
import { type DatabricksClient, asAccountAdmin } from "./client.ts";

/** The workspace permission that makes a principal a workspace admin. */
const ADMIN = "ADMIN";

const permissionAssignmentList = z.object({
  permission_assignments: z
    .array(
      z.object({
        principal: z.object({
          principal_id: z.number().optional(),
          service_principal_name: z.string().optional(),
        }),
        permissions: z.array(z.string()).optional(),
      })
    )
    .optional(),
});

const assignmentsPath = (workspaceId: string) =>
  `/workspaces/${encodeURIComponent(workspaceId)}/permissionassignments`;

/**
 * The workspace permissions the account-level permission assignment API
 * gives a service principal, or `undefined` when it has no assignment there.
 * Reading it needs account admin.
 */
export const workspaceAssignment = async (
  client: DatabricksClient,
  workspaceId: string,
  principal: { id: string; applicationId: string }
): Promise<string[] | undefined> => {
  const { context } = client;
  const { permission_assignments = [] } = parse({
    schema: permissionAssignmentList,
    data: await asAccountAdmin(context, async () =>
      client.account({ method: "GET", path: assignmentsPath(workspaceId) })
    ),
    what: "workspace permission assignments",
    requestId: context.requestId,
  });
  // `principal_id` is an int64 that JSON parsing rounds above 2^53, so it is
  // only compared when it survived parsing exactly. `service_principal_name`,
  // the application ID, identifies the principal either way.
  const entry = permission_assignments.find(
    ({ principal: { principal_id, service_principal_name } }) =>
      (principal_id !== undefined &&
        Number.isSafeInteger(principal_id) &&
        String(principal_id) === principal.id) ||
      service_principal_name?.toLowerCase() ===
        principal.applicationId.toLowerCase()
  );
  return entry ? (entry.permissions ?? []) : undefined;
};

/**
 * Makes P0's own service principal an admin of the workspace, through the
 * account-level permission assignment API, which needs account admin and
 * works before P0 is in the workspace. It reads the assignments first, and
 * writes only when P0's principal lacks `ADMIN`. Nothing undoes it: P0 stays
 * a workspace admin, as the install requires.
 *
 * Returns whether it assigned `ADMIN` just now. A workspace may take a
 * moment to see a new assignment.
 */
export const ensureWorkspaceAdmin = async (
  client: DatabricksClient,
  workspaceId: string
): Promise<boolean> => {
  const { context } = client;
  const own = await client.ownServicePrincipal();
  const permissions = await workspaceAssignment(client, workspaceId, own);
  if (permissions?.includes(ADMIN)) return false;

  // The PUT sets the principal's whole permission list, so repeating it is
  // safe.
  await asAccountAdmin(context, async () =>
    client.account({
      method: "PUT",
      path: `${assignmentsPath(workspaceId)}/principals/${encodeURIComponent(own.id)}`,
      body: { permissions: [ADMIN] },
    })
  );
  return true;
};
