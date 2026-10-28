import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { isGlobalRole } from "../../argocd/policy.ts";
import { instance } from "../../instance.ts";
import { email, listerResponse, userBody, userId } from "../common.ts";

/**
 * A global role, as `role:<name>`: `role:readonly`, `role:admin`, or any
 * role the instance's policy names. Held to the spelling the connector
 * writes in a line (printable ASCII with no space, `,`, `#` or `"`), so a
 * role that couldn't be written fails to parse instead of reaching Argo CD.
 * The connector's own role parses, and a grant refuses it.
 */
export const globalRole = z
  .string()
  .max(253, { error: "must be an Argo CD role, as role:<name>", abort: true })
  .refine(isGlobalRole, "must be an Argo CD role, as role:<name>");

// The role to leave the user with. `null` means P0's grant of the request's
// role is over, which is a revoke: the connector removes the line for the
// role the request context names.
const policy = z.object({ role: globalRole.nullable() });

// `list` gets no request context, so every query carries the instance, as
// its `context`. `role` lists the instance's global roles, or with a `role`,
// answers `[]` or that one role: P0's check that a requested role exists
// needn't list them all. `held` answers whether the user with `email` holds
// `role` already, `[]` or one row, through any policy line, a group,
// `policy.default` or inheritance: P0's check for an existing grant.
const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("role"),
    context: instance,
    role: globalRole.optional(),
  }),
  z.object({
    type: z.literal("held"),
    context: instance,
    email,
    role: globalRole,
  }),
]);

// What every user and policy call needs besides the user and the policies:
// the instance, and the role this request is for. A revoke's policy role is
// `null`, so the request context is what names the line it removes. A grant
// names the role in both, and they must agree.
const requestContext = instance.extend({
  requestId: z.string(),
  role: globalRole,
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
