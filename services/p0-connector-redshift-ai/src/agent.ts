import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { InstallContext } from "./context.ts";
import type { RedshiftSession } from "./redshift/data-api.ts";
import { localDatabases } from "./redshift/databases.ts";
import {
  assertAgentUser,
  assertPrivilegeRole,
  quoteCatalogName,
  quoteIdentifier,
  quoteLiteral,
  quoteUserName,
} from "./sql.ts";

// Only the statements marked "ran in V1" ran against a live Redshift. The
// catalog queries for revoke run first in E1.

/** Returns `user` when Redshift has it, else `null`. */
export const findAgent = async (session: RedshiftSession, user: string) => {
  const rows = await session.query(
    `SELECT user_name FROM svv_user_info WHERE user_name = ${quoteLiteral(assertAgentUser(user))}`
  );
  return rows.length > 0 ? user : null;
};

/** Creates the agent's user. It has no password: it signs in only through
 * its IAM role. */
export const createAgent = async (session: RedshiftSession, user: string) => {
  await session
    .execute(
      `CREATE USER ${quoteUserName(assertAgentUser(user))} PASSWORD DISABLE`
    )
    .catch((error: unknown) => {
      if (
        !(error instanceof ConnectorError) ||
        error.data.type !== "already_exists"
      )
        throw error;
    });
  return user;
};

const roleExists = async (session: RedshiftSession, role: string) =>
  (
    await session.query(
      `SELECT role_name FROM svv_roles WHERE role_name = ${quoteLiteral(role)}`
    )
  ).length > 0;

/** Creates the grant's privilege role unless it exists. */
export const ensurePrivilegeRole = async (
  session: RedshiftSession,
  role: string
) => {
  if (await roleExists(session, assertPrivilegeRole(role))) return;
  await session.execute(`CREATE ROLE ${quoteIdentifier(role)}`);
};

const ownerIdOf = (user: string) =>
  `(SELECT usesysid FROM pg_user WHERE usename = ${quoteLiteral(user)})`;

// Redshift keeps a materialized view's rows in an internal `mv_tbl__` table,
// which moves with the view (V1).
const isInternalTable = (name: string) => name.startsWith("mv_tbl__");

/** The tables, views and materialized views `user` owns in `database`. */
const ownedRelations = async (
  session: RedshiftSession,
  database: string,
  user: string
) =>
  (
    await session.query<{ schema_name: string; name: string }>(
      `SELECT n.nspname AS schema_name, c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relowner = ${ownerIdOf(user)} AND c.relkind IN ('r', 'v')`,
      database
    )
  ).filter(({ name }) => !isInternalTable(name));

const ROUTINE_KINDS = { f: "FUNCTION", p: "PROCEDURE" } as const;

type RoutineKind = keyof typeof ROUTINE_KINDS;

// Redshift has no user-defined types, so argument types are built-in names
// such as `character varying`.
const ROUTINE_ARGUMENTS = /^[A-Za-z0-9 ,_]*$/;

/** The functions and procedures `user` owns in `database`. */
const ownedRoutines = async (
  session: RedshiftSession,
  database: string,
  user: string
) =>
  await session.query<{
    schema_name: string;
    name: string;
    args: string;
    kind: RoutineKind;
  }>(
    `SELECT n.nspname AS schema_name, p.proname AS name, oidvectortypes(p.proargtypes) AS args, p.prokind AS kind FROM pg_proc_info p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.proowner = ${ownerIdOf(user)}`,
    database
  );

/** The schemas `user` owns in `database`, with how many tables, views and
 * routines each still holds. */
const ownedSchemas = async (
  session: RedshiftSession,
  database: string,
  user: string
) =>
  await session.query<{ name: string; objects: number }>(
    `SELECT n.nspname AS name, (SELECT count(*) FROM pg_class c WHERE c.relnamespace = n.oid) + (SELECT count(*) FROM pg_proc p WHERE p.pronamespace = n.oid) AS objects FROM pg_namespace n WHERE n.nspowner = ${ownerIdOf(user)}`,
    database
  );

const identitiesOf = (names: string[]) => names.map(quoteLiteral).join(", ");

/** The tables and views each of `identities` holds a privilege on. */
const relationPrivileges = async (
  session: RedshiftSession,
  database: string,
  identities: string[]
) =>
  await session.query<{
    namespace_name: string;
    relation_name: string;
    identity_name: string;
  }>(
    `SELECT DISTINCT namespace_name, relation_name, identity_name FROM svv_relation_privileges WHERE identity_name IN (${identitiesOf(identities)})`,
    database
  );

/** The schemas each of `identities` holds a privilege on. */
const schemaPrivileges = async (
  session: RedshiftSession,
  database: string,
  identities: string[]
) =>
  await session.query<{ namespace_name: string; identity_name: string }>(
    `SELECT DISTINCT namespace_name, identity_name FROM svv_schema_privileges WHERE identity_name IN (${identitiesOf(identities)})`,
    database
  );

const qualified = (schema: string, name: string) =>
  `${quoteCatalogName(schema)}.${quoteCatalogName(name)}`;

const routineName = ({
  schema_name,
  name,
  args,
}: {
  schema_name: string;
  name: string;
  args: string;
}) => {
  if (!ROUTINE_ARGUMENTS.test(args)) {
    throw new ConnectorError({
      type: "unknown",
      message: "Redshift returned routine arguments P0 can't read",
      payload: { schema: schema_name, routine: name },
    });
  }
  return `${qualified(schema_name, name)}(${args})`;
};

/**
 * Empties the privilege roles, hands the user's tables and views over, and
 * drops its routines, in one database. Every write follows a read, so a
 * rerun does only what an earlier run left.
 */
const revokeIn = async (
  session: RedshiftSession,
  database: string,
  user: string,
  privilegeRoles: string[],
  owner: string
) => {
  const statements: string[] = [];
  if (privilegeRoles.length > 0) {
    for (const row of await relationPrivileges(
      session,
      database,
      privilegeRoles
    )) {
      statements.push(
        `REVOKE ALL ON TABLE ${qualified(row.namespace_name, row.relation_name)} FROM ROLE ${quoteIdentifier(row.identity_name)}`
      );
    }
    for (const row of await schemaPrivileges(
      session,
      database,
      privilegeRoles
    )) {
      statements.push(
        `REVOKE ALL ON SCHEMA ${quoteCatalogName(row.namespace_name)} FROM ROLE ${quoteIdentifier(row.identity_name)}`
      );
    }
  }
  for (const { schema_name, name } of await ownedRelations(
    session,
    database,
    user
  )) {
    // ran in V1, on a table, a view and a materialized view
    statements.push(
      `ALTER TABLE ${qualified(schema_name, name)} OWNER TO ${quoteUserName(owner)}`
    );
  }
  // Only a superuser can change a routine's or a schema's owner (V1), so
  // they are dropped.
  for (const routine of await ownedRoutines(session, database, user)) {
    statements.push(
      `DROP ${ROUTINE_KINDS[routine.kind]} ${routineName(routine)}`
    );
  }
  await session.batch(statements, database);

  const emptySchemas = (await ownedSchemas(session, database, user)).filter(
    ({ objects }) => Number(objects) === 0
  );
  await session.batch(
    emptySchemas.map(({ name }) => `DROP SCHEMA ${quoteCatalogName(name)}`),
    database
  );
};

/** What still stops `DROP USER` in one database, for the error. */
const blockersIn = async (
  session: RedshiftSession,
  database: string,
  user: string,
  privilegeRoles: string[]
) => {
  const identities = [user, ...privilegeRoles];
  return [
    ...(await ownedRelations(session, database, user)).map(
      ({ schema_name, name }) => `${database}: owns ${schema_name}.${name}`
    ),
    ...(await ownedRoutines(session, database, user)).map(
      ({ schema_name, name, kind }) =>
        `${database}: owns ${ROUTINE_KINDS[kind].toLowerCase()} ${schema_name}.${name}`
    ),
    ...(await ownedSchemas(session, database, user)).map(
      ({ name, objects }) =>
        `${database}: owns schema ${name}, which holds ${objects} objects`
    ),
    ...(await relationPrivileges(session, database, identities)).map(
      ({ namespace_name, relation_name, identity_name }) =>
        `${database}: ${identity_name} holds a privilege on ${namespace_name}.${relation_name}`
    ),
    ...(await schemaPrivileges(session, database, identities)).map(
      ({ namespace_name, identity_name }) =>
        `${database}: ${identity_name} holds a privilege on schema ${namespace_name}`
    ),
  ];
};

const MAX_LISTED_BLOCKERS = 20;

/**
 * Ends the agent's access and clears what would stop its user from being
 * dropped: revokes every role from it, empties its privilege roles, gives
 * the tables and views it owns to the object owner (or to the connector's
 * user when there is none), and drops its routines and empty schemas.
 *
 * A `REVOKE` by anyone but the grantor reports success and changes nothing,
 * so the catalog is read again at the end. Anything left is thrown as a
 * `dependency_violation` that lists it, and the revoke can be run again once
 * the customer has removed it.
 */
export const revokeAgent = async (
  session: RedshiftSession,
  logger: Logger,
  install: InstallContext,
  user: string,
  privilegeRoles: string[]
) => {
  assertAgentUser(user);
  privilegeRoles.forEach(assertPrivilegeRole);

  const roles = await session.query<{ role_name: string }>(
    `SELECT role_name FROM svv_user_grants WHERE user_name = ${quoteLiteral(user)}`
  );
  await session.batch(
    roles.map(
      ({ role_name }) =>
        `REVOKE ROLE ${quoteCatalogName(role_name)} FROM ${quoteUserName(user)}`
    )
  );

  const owner =
    install.objectOwner ??
    (
      await session.query<{ user_name: string }>(
        "SELECT current_user AS user_name"
      )
    )[0]!.user_name;
  const databases = await localDatabases(session, logger);
  for (const database of databases) {
    await revokeIn(session, database, user, privilegeRoles, owner);
  }

  const blockers: string[] = [];
  for (const database of databases) {
    blockers.push(
      ...(await blockersIn(session, database, user, privilegeRoles))
    );
  }
  if (blockers.length > 0) {
    const listed = blockers.slice(0, MAX_LISTED_BLOCKERS).join("; ");
    const more =
      blockers.length > MAX_LISTED_BLOCKERS
        ? `; and ${blockers.length - MAX_LISTED_BLOCKERS} more`
        : "";
    throw new ConnectorError({
      type: "dependency_violation",
      message: `P0 can't drop ${user} until these are removed: ${listed}${more}`,
      payload: { user, nBlockers: blockers.length },
    });
  }
  logger.info(
    { nRoles: roles.length, nDatabases: databases.length },
    "revoked the agent's access"
  );
};

/** Drops the agent's user, then its privilege roles. Either one already
 * gone counts as done. */
export const dropAgent = async (
  session: RedshiftSession,
  user: string,
  privilegeRoles: string[]
) => {
  // `DROP USER IF EXISTS` ran in V1.
  await session.execute(
    `DROP USER IF EXISTS ${quoteUserName(assertAgentUser(user))}`
  );
  for (const role of privilegeRoles) {
    if (await roleExists(session, assertPrivilegeRole(role))) {
      await session.execute(`DROP ROLE ${quoteIdentifier(role)}`);
    }
  }
};
