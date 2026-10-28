import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
import type { JsonValue } from "type-fest";
import { z } from "zod";

export const pgClientParams = z.object({
  p0User: z.string(),
  host: z.string(),
  // 65535 is the highest TCP port (input validation only)
  port: z.coerce.number().int().min(1).max(65535),
  database: z.string(),
  cloud: z.enum(["rds", "cloudsql", "localhost"]).optional().default("rds"),
});

export const requestContext = z.object({
  requestId: z.string(),
  db: pgClientParams,
});

export type PgRequestContext = z.infer<typeof requestContext>;
export type PgClientParams = z.infer<typeof pgClientParams>;

const username = z.string().min(1);
export const rolename = z.string().min(1);
export const userBody = username;
export const userId = username;
export const resourceId = rolename;
export const resourceBody = rolename;

export const listerResponse = z
  .object({
    key: z.string().min(1),
    value: z.string().min(1),
    group: z.string().min(1).optional(),
  })
  .array();

/**
 * Builds the parsers for a Postgres access type. Every access type shares the
 * same users, resources and request context — a Postgres role — so an access
 * type only supplies its own policy shape and the entities its lister serves.
 */
export const newPgAccessSpec = <
  PolicySchema extends z.ZodType<JsonValue>,
  ListerQuerySchema extends z.ZodType<JsonValue & { type: string }>,
>(
  policy: PolicySchema,
  query: ListerQuerySchema
) => {
  const schema = {
    userBody,
    userId,
    resourceBody,
    policy,
    resourceId,
    listerQuery: query,
    listerResponse,
    requestContext,
  };

  return newZodResourceHierarchyParsers(schema);
};
