import { z } from "zod";

import {
  newPgAccessSpec,
  pgClientParams,
  rolename,
} from "../common/definition.ts";

const policy = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("role"),
      rolename,
    })
    .meta({
      description:
        "GRANT <rolename> TO <role>, see https://www.postgresql.org/docs/current/role-membership.html",
    }),
]);

export const spec = newPgAccessSpec(
  policy,
  z.object({
    type: z.enum(["role", "database"]),
    context: pgClientParams,
  })
);
