import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  agentUser,
  listerQuery,
  listerResponse,
  requestContext,
} from "../../context.ts";
import { PRIVILEGE_ROLE_PATTERN, isObjectName } from "../../sql.ts";

export const PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

/**
 * One privilege on one object: a database (`DB`), a schema (`DB.SCHEMA`), or
 * a table or view (`DB.SCHEMA.TABLE`). A database or schema entry covers
 * every table and view that exists in it when access is granted.
 */
const policy = z.object({
  privilege: z.enum(PRIVILEGES),
  object: z.string().refine(isObjectName, "Invalid object name"),
});

export type ObjectsPolicy = z.infer<typeof policy>;

/** The privileges go to the grant's privilege role, `p0_agent_<id>`, which
 * P0 names; the role is then granted to the agent's user. */
export const objectsRequestContext = requestContext.extend({
  privilegeRole: z.string().regex(PRIVILEGE_ROLE_PATTERN),
});

export type ObjectsRequestContext = z.infer<typeof objectsRequestContext>;

export const schema = {
  userBody: agentUser,
  userId: agentUser,
  policy,
  listerQuery,
  listerResponse,
  requestContext: objectsRequestContext,
};

export const spec = newZodResourceRootParsers(schema);
