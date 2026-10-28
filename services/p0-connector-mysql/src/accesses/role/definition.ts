import { newZodResourceHierarchyParsers } from "@p0security/connector";
import { z } from "zod";

// MySQL privilege keywords that may appear in GRANT/REVOKE statements.
// Because MySQL privileges are SQL keywords (not identifiers), they cannot be
// safely parameterized with ?? (which would backtick-quote them). Validating
// against this allowlist before interpolation prevents SQL injection.
const VALID_MYSQL_PRIVILEGES = [
  "ALL",
  "ALL PRIVILEGES",
  "ALTER",
  "ALTER ROUTINE",
  "CREATE",
  "CREATE ROUTINE",
  "CREATE TEMPORARY TABLES",
  "CREATE VIEW",
  "DELETE",
  "DROP",
  "EVENT",
  "EXECUTE",
  "INDEX",
  "INSERT",
  "LOCK TABLES",
  "REFERENCES",
  "SELECT",
  "SHOW VIEW",
  "TRIGGER",
  "UPDATE",
] as const;

export const mysqlClientParams = z.object({
  p0User: z.string(),
  host: z.string(),
  // 65535 is the highest TCP port (input validation only)
  port: z.coerce.number().int().min(1).max(65535),
  cloud: z.enum(["rds", "cloudsql", "localhost"]).optional().default("rds"),
});

const username = z.string().min(1);
const rolename = z.string().min(1);

const userBody = username;
const userId = username;
const resourceId = rolename;
const resourceBody = rolename;
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
      privilege: z.preprocess(
        (arg) => (typeof arg === "string" ? arg.toLocaleUpperCase() : arg),
        z.enum(VALID_MYSQL_PRIVILEGES)
      ),
      schema: z.string().min(1).meta({
        description:
          "The object to which the privilege applies, e.g. schemas & tables, schema.table or schema.*",
      }),
    })
    .meta({
      description:
        "GRANT <privilege> ON SCHEMA <schema> TO <role>, see http://postgresql.org/docs/current/ddl-priv.html",
    }),
  z
    .object({
      type: z.literal("table-privilege"),
      privilege: z.preprocess(
        (arg) => (typeof arg === "string" ? arg.toLocaleUpperCase() : arg),
        z.enum(VALID_MYSQL_PRIVILEGES)
      ),
      schema: z.string().min(1),
      table: z.string().min(1).meta({
        description:
          "The object to which the privilege applies, e.g. tables, schema.table or schema.*",
      }),
    })
    .meta({
      description:
        "GRANT <privilege> ON TABLE <table> TO <role>, see http://postgresql.org/docs/current/ddl-priv.html",
    }),
]);

const listerQuery = z.object({
  type: z.enum(["role", "database"]),
  context: mysqlClientParams,
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export const requestContext = z.object({
  requestId: z.string(),
  db: mysqlClientParams,
});

export const schema = {
  userBody,
  userId,
  resourceBody,
  policy,
  resourceId,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceHierarchyParsers(schema);
