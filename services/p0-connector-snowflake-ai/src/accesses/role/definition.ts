import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import {
  agentName,
  listerQuery,
  listerResponse,
  requestContext,
} from "../../context.ts";
import { isIdentifierPart } from "../../sql.ts";

/** One existing customer role, granted to the wrapper role. No role is
 * refused here: P0's policies are the only guard on this access type. */
const policy = z.object({
  role: z.string().refine(isIdentifierPart, "Invalid role name"),
});

export type RolePolicy = z.infer<typeof policy>;

export const schema = {
  userBody: agentName,
  userId: agentName,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
