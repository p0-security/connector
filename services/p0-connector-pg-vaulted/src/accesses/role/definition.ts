import {
  type ResourceRootSchemaOf,
  newZodResourceRootParsers,
} from "@p0security/connector-core";
import { z } from "zod";

import {
  grantLogin,
  listerQuery,
  listerResponse,
  requestContext,
} from "../../context.ts";
import { isIdentifier } from "../../identifier.ts";

const rolename = z.string().min(1).refine(isIdentifier, "Invalid role name");

// shape copied from `policy` in services/p0-connector-pg/src/accesses/role/definition.ts
/** One approved role, granted to the grant login. */
const policy = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("role"),
      rolename,
    })
    .meta({
      description:
        "GRANT <rolename> TO <grant login>, see https://www.postgresql.org/docs/current/role-membership.html",
    }),
]);

export const schema = {
  userBody: grantLogin,
  userId: grantLogin,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

export type RoleSchema = ResourceRootSchemaOf<typeof spec>;
