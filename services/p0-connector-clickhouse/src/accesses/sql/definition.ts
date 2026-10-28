import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
import { z } from "zod";

import { LEVELS } from "../../levels.ts";
import { accessSchemas, objectName } from "../common/definition.ts";

/**
 * A level on one object in the service. It becomes
 * `sql-console:database:access` on the service, with one GRANT statement per
 * element of `tags.grants`. A view is granted as itself only: nothing is
 * added for the tables it reads.
 */
export const policy = z
  .object({
    type: z.literal("sql"),
    level: z.enum(LEVELS).meta({
      description:
        "The level to grant: read, write or admin. Each holds the one below it.",
    }),
    object: z
      .object({
        database: objectName.optional(),
        table: objectName.optional(),
      })
      .refine(
        ({ database, table }) => table === undefined || database !== undefined,
        "names a table without its database"
      )
      .meta({
        description:
          "What the level is on: the whole service ({}), a database ({database}), or a table, view, materialized view or dictionary ({database, table}).",
      }),
  })
  .meta({ description: "GRANT <level privileges> ON <object>" });

export type SqlPolicy = z.infer<typeof policy>;

export const spec = newZodResourceHierarchyParsers({
  ...accessSchemas,
  policy,
});
