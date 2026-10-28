import { z } from "zod";

import {
  newPgAccessSpec,
  pgClientParams,
  rolename,
} from "../common/definition.ts";

export const SCHEMA_PRIVILEGES = ["CREATE", "USAGE", "ALL PRIVILEGES"] as const;

export const TABLE_PRIVILEGES = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "TRUNCATE",
  "REFERENCES",
  "TRIGGER",
  "ALL PRIVILEGES",
] as const;

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
  z
    .object({
      type: z.literal("schema-privilege"),
      privilege: z
        .string()
        .min(1)
        .meta({
          description: `The privilege to grant, in any case: ${SCHEMA_PRIVILEGES.join(", ")} (or ALL, for ALL PRIVILEGES)`,
        }),
      schema: z.string().min(1).meta({
        description:
          "The schema to which the privilege applies, e.g. public. `ON SCHEMA` names a single schema; use a table-privilege policy to reach its tables.",
      }),
    })
    .meta({
      description:
        "GRANT <privilege> ON SCHEMA <schema> TO <role>, see http://postgresql.org/docs/current/ddl-priv.html",
    }),
  z
    .object({
      type: z.literal("table-privilege"),
      privilege: z
        .string()
        .min(1)
        .meta({
          description: `The privilege to grant, in any case: ${TABLE_PRIVILEGES.join(", ")} (or ALL, for ALL PRIVILEGES)`,
        }),
      table: z.string().min(1).meta({
        description:
          "The table to which the privilege applies, e.g. table or schema.table. Must name a concrete table; wildcards are not accepted.",
      }),
    })
    .meta({
      description:
        "GRANT <privilege> ON TABLE <table> TO <role>, see http://postgresql.org/docs/current/ddl-priv.html",
    }),
]);

export const spec = newPgAccessSpec(
  policy,
  z.object({
    type: z.enum(["database"]),
    context: pgClientParams,
  })
);
