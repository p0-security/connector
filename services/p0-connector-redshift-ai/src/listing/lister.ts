import type { Logger } from "@p0security/connector-core";

import type { ListerQuery, ListerResponse } from "../context.ts";
import type { RedshiftSession } from "../redshift/data-api.ts";
import { localDatabases } from "../redshift/databases.ts";
import {
  CONNECTOR_ADMIN_ROLE,
  PRIVILEGE_ROLE_PATTERN,
  isIdentifier,
} from "../sql.ts";

const PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

type Privilege = (typeof PRIVILEGES)[number];

const isPrivilege = (value: string): value is Privilege =>
  (PRIVILEGES as readonly string[]).includes(value);

const isSystemSchema = (name: string) =>
  name.startsWith("pg_") ||
  name === "information_schema" ||
  name === "catalog_history";

// Redshift keeps a materialized view's rows in an internal `mv_tbl__` table.
const isInternalTable = (name: string) => name.startsWith("mv_tbl__");

/** Customer roles: every role except Redshift's `sys:` roles and P0's own. */
const listRoles = async (session: RedshiftSession) =>
  (
    await session.query<{ role_name: string }>(
      "SELECT role_name FROM svv_roles"
    )
  )
    .map(({ role_name }) => role_name)
    .filter(
      (name) =>
        isIdentifier(name) &&
        name !== CONNECTOR_ADMIN_ROLE &&
        !PRIVILEGE_ROLE_PATTERN.test(name)
    )
    .sort()
    .map((name) => ({ key: name, value: name }));

/** What the connector's user can grant in one database. */
type Grantable = {
  /** Every user schema, and whether the connector can grant its `USAGE`. */
  schemas: Map<string, boolean>;
  /** Every table and view, by `schema.name`, with the privileges the
   * connector can grant on it. */
  relations: Map<string, { schema: string; name: string; can: Set<Privilege> }>;
};

/**
 * Reads what the connector's user owns or holds `WITH GRANT OPTION` on. An
 * owner can grant every privilege. Redshift allows `WITH GRANT OPTION` only
 * to a user, so roles are not read.
 */
const grantableIn = async (
  session: RedshiftSession,
  database: string
): Promise<Grantable> => {
  const me = "(SELECT usesysid FROM pg_user WHERE usename = current_user)";
  const schemaRows = await session.query<{ name: string; owned: boolean }>(
    `SELECT nspname AS name, nspowner = ${me} AS owned FROM pg_namespace`,
    database
  );
  const usageRows = await session.query<{ namespace_name: string }>(
    "SELECT namespace_name FROM svv_schema_privileges WHERE identity_name = current_user AND privilege_type = 'USAGE' AND admin_option",
    database
  );
  const relationRows = await session.query<{
    schema_name: string;
    name: string;
    owned: boolean;
  }>(
    `SELECT n.nspname AS schema_name, c.relname AS name, c.relowner = ${me} AS owned FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'v')`,
    database
  );
  // ran in V1, as the connector
  const privilegeRows = await session.query<{
    namespace_name: string;
    relation_name: string;
    privilege_type: string;
  }>(
    "SELECT namespace_name, relation_name, privilege_type FROM svv_relation_privileges WHERE identity_name = current_user AND admin_option",
    database
  );

  const usage = new Set(usageRows.map(({ namespace_name }) => namespace_name));
  const schemas = new Map(
    schemaRows
      .filter(({ name }) => !isSystemSchema(name))
      .map(({ name, owned }) => [name, owned || usage.has(name)])
  );
  const relations: Grantable["relations"] = new Map();
  for (const { schema_name, name, owned } of relationRows) {
    if (!schemas.has(schema_name) || isInternalTable(name)) continue;
    relations.set(`${schema_name}.${name}`, {
      schema: schema_name,
      name,
      can: new Set(owned ? PRIVILEGES : []),
    });
  }
  for (const row of privilegeRows) {
    const relation = relations.get(
      `${row.namespace_name}.${row.relation_name}`
    );
    const privilege = row.privilege_type.toUpperCase();
    if (relation && isPrivilege(privilege)) relation.can.add(privilege);
  }
  return { schemas, relations };
};

const GROUPS = { 1: "Database", 2: "Schema", 3: "Table" } as const;

const entry = (privilege: Privilege, ...parts: string[]) => {
  const key = `${privilege}:${parts.join(".")}`;
  return {
    key,
    value: key,
    group: GROUPS[parts.length as keyof typeof GROUPS],
  };
};

/**
 * The entries one database offers, as `PRIVILEGE:OBJECT`. A grant gives
 * `USAGE` on each schema it covers and the privilege on each table and view
 * in it, so an entry is listed only when the connector can grant all of
 * these, and a schema or database only when it holds at least one table.
 */
const entriesIn = (database: string, { schemas, relations }: Grantable) => {
  const entries: ListerResponse = [];
  const all = [...relations.values()];
  const canAll = (
    privilege: Privilege,
    covered: typeof all,
    schemaNames: string[]
  ) =>
    covered.length > 0 &&
    schemaNames.every((schema) => schemas.get(schema)) &&
    covered.every(({ can }) => can.has(privilege));

  if (isIdentifier(database)) {
    for (const privilege of PRIVILEGES) {
      if (canAll(privilege, all, [...schemas.keys()]))
        entries.push(entry(privilege, database));
    }
  }
  for (const schema of schemas.keys()) {
    if (!isIdentifier(database) || !isIdentifier(schema)) continue;
    const covered = all.filter((relation) => relation.schema === schema);
    for (const privilege of PRIVILEGES) {
      if (canAll(privilege, covered, [schema]))
        entries.push(entry(privilege, database, schema));
    }
    for (const relation of covered) {
      if (!schemas.get(schema) || !isIdentifier(relation.name)) continue;
      for (const privilege of PRIVILEGES) {
        if (relation.can.has(privilege))
          entries.push(entry(privilege, database, schema, relation.name));
      }
    }
  }
  return entries;
};

/** Grantable objects in every local database. */
const listObjects = async (session: RedshiftSession, logger: Logger) => {
  const entries: ListerResponse = [];
  for (const database of await localDatabases(session, logger)) {
    entries.push(...entriesIn(database, await grantableIn(session, database)));
  }
  return entries;
};

type Lister = (
  session: RedshiftSession,
  logger: Logger
) => Promise<ListerResponse>;

const listers: Record<ListerQuery["type"], Lister> = {
  role: listRoles,
  object: listObjects,
};

/**
 * The lister for each request parameter. A name the connector would refuse
 * (one that needs quoting beyond letters, digits, `_` and `$`) is left out.
 */
export const listFor = (
  session: RedshiftSession,
  logger: Logger,
  type: ListerQuery["type"]
) => listers[type](session, logger);
