import { z } from "zod";

import type { OwnIdentity, OwnServicePrincipal } from "../databricks/client.ts";
import { accountContext, workspaceUrl } from "../databricks/context.ts";
import {
  WORKSPACE_PAIR_ERROR,
  hasWorkspacePair,
  workspaceId,
} from "../databricks/workspaces.ts";

/**
 * What an install verifier sends: the account to authenticate to and, for a
 * workspace item, the workspace's ID and the URL the customer entered for
 * it, which the connector binds to the ID. Each `require` field asks for a
 * check that only an install turning on the matching access type needs.
 *
 * Strict, so a caller sending a field this schema doesn't know (a
 * misspelled field, say) fails instead of validating less and reporting
 * success.
 */
export const installValidationInput = z
  .strictObject({
    ...accountContext.shape,
    workspaceId: workspaceId.optional(),
    workspaceUrl: workspaceUrl.optional(),
    /** Fail unless the principal holds account admin. Read through account SCIM. */
    requireAccountAdmin: z.boolean().optional(),
    /** Fail unless the workspace's SCIM /Me lists the admins group. Needs a workspace. */
    requireWorkspaceAdmin: z.boolean().optional(),
  })
  .refine(hasWorkspacePair, {
    error: WORKSPACE_PAIR_ERROR,
    path: ["workspaceUrl"],
  })
  .refine(
    (input) => !input.requireWorkspaceAdmin || input.workspaceId !== undefined,
    {
      error: "requireWorkspaceAdmin needs a workspace",
      path: ["requireWorkspaceAdmin"],
    }
  );

/** What install validation returns. */
export type InstallValidation = {
  /** The principal in account SCIM. Read only when `requireAccountAdmin` is set. */
  servicePrincipal: OwnServicePrincipal | null;
  /** What P0 checked in the workspace, when one was given. */
  workspace: {
    /** The principal as the workspace's SCIM /Me reports it. */
    identity: OwnIdentity;
    /** The workspace's Unity Catalog metastore, from current-metastore-assignment. */
    metastoreId: string;
    /** Whether /Me lists the workspace's `admins` group. */
    isAdmin: boolean;
  } | null;
};

export type InstallValidationInput = z.input<typeof installValidationInput>;
