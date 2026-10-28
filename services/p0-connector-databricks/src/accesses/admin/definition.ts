import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  accountContext,
  databricksId,
  workspaceUrl,
} from "../../databricks/context.ts";
import {
  WORKSPACE_PAIR_ERROR,
  hasWorkspacePair,
  workspaceId,
} from "../../databricks/workspaces.ts";
import {
  userBody as commonUserBody,
  listerResponse,
  operation,
} from "../common/definition.ts";

/**
 * The user's account SCIM ID, which is the principal ID the workspace
 * assignment API takes and the `{id}` the SCIM `PATCH` takes. The account
 * and the workspace's SCIM proxy report the same ID.
 */
const userId = databricksId;

/**
 * The user to find. `email` is the requestor's P0 email, which domain
 * verification checks in `validation`. `userId`, when present, is the account
 * SCIM ID P0 recorded at stage, and the user is then read by it alone: a
 * revoke still finds a user whose emails changed since.
 */
export const userBody = commonUserBody.extend({ userId: userId.optional() });

export type UserBody = z.infer<typeof userBody>;

// The resource is the workspace when the request context names one, and the
// account otherwise, so each call carries at most the one matching policy. A
// grant always carries it, and a call without it is a revoke. A revoke
// carries it only while another open request on the scope still holds the
// role.
const policy = z.enum(["WORKSPACE_ADMIN", "ACCOUNT_ADMIN"]);

/**
 * A user's own (direct) assignment on a workspace. `none` means the user has
 * no assignment of their own, even if a group gives them access.
 */
export const workspaceAssignment = z.enum(["none", "USER", "ADMIN"]);

/**
 * The user's own assignment before P0 granted, which revoke restores. Never
 * `ADMIN`, which is what keeps a revoke from raising access. Account admin has
 * no prior state to restore, so the control plane sends `none` for it.
 */
const priorAssignment = workspaceAssignment.exclude(["ADMIN"]);

const requestContext = accountContext
  .extend({
    /** Both set for workspace admin, both absent for account admin. */
    workspaceId: workspaceId.optional(),
    workspaceUrl: workspaceUrl.optional(),
    priorAssignment,
    operation,
  })
  .refine(hasWorkspacePair, {
    error: WORKSPACE_PAIR_ERROR,
    path: ["workspaceUrl"],
  });

/**
 * The user's current role on the workspace, or on the account when the
 * workspace is absent. Returns one item keyed `none`, `USER` or `ADMIN`.
 * `list` gets no request context, so the query carries the account to act in.
 * P0 lists workspaces from its own installed items, so there is no
 * `workspaces` query.
 */
const listerQuery = z
  .object({
    type: z.literal("priorAssignment"),
    context: accountContext,
    userId,
    workspaceId: workspaceId.optional(),
    workspaceUrl: workspaceUrl.optional(),
  })
  .refine(hasWorkspacePair, {
    error: WORKSPACE_PAIR_ERROR,
    path: ["workspaceUrl"],
  });

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
