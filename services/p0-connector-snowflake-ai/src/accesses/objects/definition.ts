import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import {
  agentName,
  listerQuery,
  listerResponse,
  requestContext,
} from "../../context.ts";
import { isObjectName } from "../../sql.ts";

export const PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

/**
 * One privilege on one object: a database (`DB`), a schema (`DB.SCHEMA`), or
 * a table or view (`DB.SCHEMA.OBJECT`). A database or schema entry covers
 * every table and view that exists in it when access is granted.
 */
const policy = z.object({
  privilege: z.enum(PRIVILEGES),
  object: z.string().refine(isObjectName, "Invalid object name"),
});

export type ObjectsPolicy = z.infer<typeof policy>;

export const schema = {
  userBody: agentName,
  userId: agentName,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
