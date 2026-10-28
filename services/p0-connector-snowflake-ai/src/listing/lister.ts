import { throwAssertNever } from "@p0security/connector";

import type { ListerQuery } from "../context.ts";
import type { SnowflakeSession } from "../snowflake/client.ts";
import { isIdentifierPart, isObjectName } from "../sql.ts";

// Unverified against a live account (INT-617): `SHOW WAREHOUSES` lists only
// the warehouses the connector's role can see. `ACCOUNT_USAGE` has no
// warehouse view to list the rest from.

/**
 * Databases, schemas, tables and views, from `ACCOUNT_USAGE`, which lists
 * every object in the account but lags new objects by up to about 90 minutes.
 * `SHOW` would list only what the connector's role can see.
 */
export const OBJECTS_QUERY = `
SELECT DATABASE_NAME AS NAME, 'Database' AS KIND
  FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES WHERE DELETED IS NULL
UNION ALL
SELECT CATALOG_NAME || '.' || SCHEMA_NAME, 'Schema'
  FROM SNOWFLAKE.ACCOUNT_USAGE.SCHEMATA
  WHERE DELETED IS NULL AND SCHEMA_NAME <> 'INFORMATION_SCHEMA'
UNION ALL
SELECT TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME, 'Table'
  FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
  WHERE DELETED IS NULL AND TABLE_TYPE = 'BASE TABLE'
UNION ALL
SELECT TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME, 'View'
  FROM SNOWFLAKE.ACCOUNT_USAGE.VIEWS
  WHERE DELETED IS NULL AND TABLE_SCHEMA <> 'INFORMATION_SCHEMA'
ORDER BY 1`;

/**
 * Whether a listed name is granted as listed. P0 upper-cases every name a
 * request carries, so a name with lower-case letters (created quoted) would
 * be granted as a different, upper-case object. It is left out.
 */
const isGrantedAsListed = (name: string) => name === name.toUpperCase();

const named = (names: string[], isValid: (name: string) => boolean) =>
  names
    .filter((name) => isValid(name) && isGrantedAsListed(name))
    .map((name) => ({ key: name, value: name }));

/**
 * The lister for each request parameter. A name the connector would refuse
 * (one that needs quoting beyond letters, digits, `_` and `$`) or that P0
 * would upper-case into another name is left out. Tables are base tables
 * only, so that views, which `ACCOUNT_USAGE.TABLES` also lists, aren't listed
 * twice. Unverified against a live account (INT-617): which other kinds of
 * table show as base tables (dynamic tables may), and whether P0's grants
 * work on them.
 */
export const listFor = async (
  session: SnowflakeSession,
  type: ListerQuery["type"]
) => {
  switch (type) {
    case "role": {
      const rows = await session.query<{ name: string }>("SHOW ROLES");
      return named(
        rows.map(({ name }) => name),
        isIdentifierPart
      );
    }
    case "warehouse": {
      const rows = await session.query<{ name: string }>("SHOW WAREHOUSES");
      return named(
        rows.map(({ name }) => name),
        isIdentifierPart
      );
    }
    case "object": {
      // `ACCOUNT_USAGE.TABLES` has rows with no catalog or schema, and the
      // concatenation makes their name NULL.
      const rows = await session.query<{ NAME: string | null; KIND: string }>(
        OBJECTS_QUERY
      );
      return rows.flatMap(({ NAME, KIND }) =>
        NAME !== null && isObjectName(NAME) && isGrantedAsListed(NAME)
          ? [{ key: NAME, value: NAME, group: KIND }]
          : []
      );
    }
    default:
      throw throwAssertNever(type);
  }
};
