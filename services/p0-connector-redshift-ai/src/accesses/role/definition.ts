import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  agentUser,
  listerQuery,
  listerResponse,
  requestContext,
} from "../../context.ts";
import {
  CONNECTOR_ADMIN_ROLE,
  PRIVILEGE_ROLE_PATTERN,
  isIdentifier,
} from "../../sql.ts";

/** One existing customer role, granted to the agent's user. P0's own roles
 * are refused; `sys:` roles fail the name check. */
const policy = z.object({
  role: z
    .string()
    .refine(isIdentifier, "Invalid role name")
    .refine(
      (role) =>
        role !== CONNECTOR_ADMIN_ROLE && !PRIVILEGE_ROLE_PATTERN.test(role),
      "P0 doesn't grant its own roles"
    ),
});

export type RolePolicy = z.infer<typeof policy>;

export const schema = {
  userBody: agentUser,
  userId: agentUser,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
