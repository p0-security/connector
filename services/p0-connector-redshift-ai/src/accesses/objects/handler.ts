import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import { ensurePrivilegeRole } from "../../agent.ts";
import type { RedshiftSession } from "../../redshift/data-api.ts";
import {
  objectNameParts,
  quoteCatalogName,
  quoteIdentifier,
  quoteUserName,
} from "../../sql.ts";
import { type AgentAccess, newAgentAccessRouter } from "../router.ts";
import {
  type ObjectsPolicy,
  type ObjectsRequestContext,
  spec,
} from "./definition.ts";

const isSystemSchema = (name: string) =>
  name.startsWith("pg_") ||
  name === "information_schema" ||
  name === "catalog_history";

/** The user schemas of `database`, quoted. */
const schemasOf = async (session: RedshiftSession, database: string) =>
  (
    await session.query<{ schema_name: string; schema_type: string }>(
      `SHOW SCHEMAS FROM DATABASE ${quoteIdentifier(database)};`
    )
  )
    .filter(
      ({ schema_name, schema_type }) =>
        schema_type === "local" && !isSystemSchema(schema_name)
    )
    .map(({ schema_name }) => quoteCatalogName(schema_name));

/**
 * The grants for one entry, run in its database: `USAGE` on each schema,
 * then the privilege on the table, or on every table and view that exists in
 * each schema now. `ALL TABLES` takes in views. There are no future grants,
 * so objects created during the grant are not covered.
 */
export const grantStatements = (
  role: string,
  { privilege, object }: ObjectsPolicy,
  schemas: string[]
) => {
  const parts = objectNameParts(object)!;
  const grantee = `ROLE ${quoteIdentifier(role)}`;
  return schemas.flatMap((schema) => [
    `GRANT USAGE ON SCHEMA ${schema} TO ${grantee}`,
    parts.length === 3
      ? `GRANT ${privilege} ON TABLE ${schema}.${quoteIdentifier(parts[2]!)} TO ${grantee}`
      : `GRANT ${privilege} ON ALL TABLES IN SCHEMA ${schema} TO ${grantee}`,
  ]);
};

/** The schemas an entry names, quoted: its own, or every one in its
 * database. */
const schemasFor = async (
  session: RedshiftSession,
  { object }: ObjectsPolicy
) => {
  const [database, schema] = objectNameParts(object)!;
  return schema === undefined
    ? await schemasOf(session, database!)
    : [quoteIdentifier(schema)];
};

const objectsAccess: AgentAccess<ObjectsPolicy, ObjectsRequestContext> = {
  grant: async (session, { privilegeRole }, user, policies) => {
    await ensurePrivilegeRole(session, privilegeRole);
    const byDatabase = new Map<string, ObjectsPolicy[]>();
    for (const policy of policies) {
      const database = objectNameParts(policy.object)![0]!;
      byDatabase.set(database, [...(byDatabase.get(database) ?? []), policy]);
    }
    // A grant runs in the object's own database: Redshift grants nothing
    // across databases.
    for (const [database, entries] of byDatabase) {
      const statements = new Set<string>();
      for (const policy of entries) {
        const schemas = await schemasFor(session, policy);
        for (const statement of grantStatements(privilegeRole, policy, schemas))
          statements.add(statement);
      }
      await session.batch([...statements], database);
    }
    await session.execute(
      `GRANT ROLE ${quoteIdentifier(privilegeRole)} TO ${quoteUserName(user)}`
    );
  },
  privilegeRoles: ({ privilegeRole }) => [privilegeRole],
};

/** The object-privileges access type: each policy is one privilege on one
 * object, granted to the privilege role. */
export const router = (t: AnyConnectorTRPCInstance) =>
  newAgentAccessRouter(t, spec, objectsAccess);
