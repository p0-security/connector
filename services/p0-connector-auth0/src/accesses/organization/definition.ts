import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import {
  auth0Id,
  baseRequestContext,
  listerQuery,
  listerResponse,
  userBody,
  userId,
} from "../common/definition.ts";

// The organization to add the user to, and optionally a tenant role to assign
// them in it. `null` takes back what P0 added, as the request context says.
const policy = z
  .object({ organizationId: auth0Id, roleId: auth0Id.optional() })
  .nullable();

/**
 * What P0 grants, and what it recorded at stage about the user's standing in
 * the organization. The connector can't keep what it learns during a grant,
 * so a revoke reads this to take back only what P0 added.
 */
const requestContext = baseRequestContext.extend({
  organizationId: auth0Id,
  roleId: auth0Id.optional(),
  /** The user was a member before P0 granted anything. A revoke then never removes the membership. */
  wasMember: z.boolean(),
  /** The member's roles in the organization at stage, which a revoke never removes. */
  priorRoleIds: z.array(auth0Id),
});

export type OrganizationRequestContext = z.infer<typeof requestContext>;

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
