import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
} from "@p0security/connector-core";

import type { SnowflakeSession } from "../../snowflake/client.ts";
import {
  objectNameParts,
  quoteIdentifier,
  quoteObjectName,
} from "../../sql.ts";
import { type GrantPolicy, newAgentAccessRouter } from "../router.ts";
import { type ObjectsPolicy, spec } from "./definition.ts";

/**
 * The grants for a database or schema entry: USAGE on the containers, then
 * the privilege on every existing table, and SELECT on every existing view.
 * INSERT, UPDATE and DELETE are not valid on views. There are no FUTURE
 * grants, so objects created during the grant are not covered.
 */
export const containerGrantStatements = (
  role: string,
  { privilege, object }: ObjectsPolicy
) => {
  const parts = objectNameParts(object);
  const grantee = quoteIdentifier(role);
  const database = quoteIdentifier(parts[0]);
  const usage = [`GRANT USAGE ON DATABASE ${database} TO ROLE ${grantee}`];
  if (parts.length === 1) {
    usage.push(
      `GRANT USAGE ON ALL SCHEMAS IN DATABASE ${database} TO ROLE ${grantee}`
    );
  } else {
    usage.push(
      `GRANT USAGE ON SCHEMA ${quoteObjectName(parts.slice(0, 2).join("."))} TO ROLE ${grantee}`
    );
  }
  if (parts.length === 3) return usage;

  const scope =
    parts.length === 1
      ? `IN DATABASE ${database}`
      : `IN SCHEMA ${quoteObjectName(object)}`;
  return [
    ...usage,
    `GRANT ${privilege} ON ALL TABLES ${scope} TO ROLE ${grantee}`,
    ...(privilege === "SELECT"
      ? [`GRANT SELECT ON ALL VIEWS ${scope} TO ROLE ${grantee}`]
      : []),
  ];
};

export const objectGrantStatement = (
  role: string,
  { privilege, object }: ObjectsPolicy,
  kind: "TABLE" | "VIEW"
) =>
  `GRANT ${privilege} ON ${kind} ${quoteObjectName(object)} TO ROLE ${quoteIdentifier(role)}`;

/**
 * Grants a table or view entry. The entry doesn't say which it is, so the
 * grant is tried on a table, then, for SELECT, on a view. Asking first would
 * need the connector's role to see the object, which `SHOW` does not promise.
 */
const grantObject = async (
  session: SnowflakeSession,
  role: string,
  policy: ObjectsPolicy
) => {
  try {
    await session.execute(objectGrantStatement(role, policy, "TABLE"));
  } catch (error) {
    if (
      !(error instanceof ConnectorError) ||
      error.data.type !== "object_not_found"
    )
      throw error;
    if (policy.privilege !== "SELECT") {
      throw new ConnectorError({
        type: "object_not_found",
        message: `No table ${policy.object}; ${policy.privilege} can be granted only on tables`,
        payload: { object: policy.object, privilege: policy.privilege },
      });
    }
    await session.execute(objectGrantStatement(role, policy, "VIEW"));
  }
};

const grantObjects: GrantPolicy<ObjectsPolicy> = async (
  session,
  role,
  policy
) => {
  for (const statement of containerGrantStatements(role, policy))
    await session.execute(statement);
  if (objectNameParts(policy.object).length === 3)
    await grantObject(session, role, policy);
};

/** The object-privileges access type: each policy is one privilege on one
 * object, granted to the wrapper role. */
export const router = (t: AnyConnectorTRPCInstance) =>
  newAgentAccessRouter(t, spec, grantObjects);
