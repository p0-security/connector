import { isEqual } from "lodash-es";

import type { EndpointRequest, ListedEndpoint } from "../cloud/client.ts";

/**
 * P0's own Query API endpoints: saved, read-only queries the connector
 * creates on a service the first time it reads there, and runs to read what
 * it lists. Their SQL is fixed here. A request's values only ever reach them
 * as typed `queryVariables`, never in the SQL.
 */

/** Every P0 endpoint's name. */
export const P0_ENDPOINT_NAMES = ["p0_objects"] as const;

export type P0EndpointName = (typeof P0_ENDPOINT_NAMES)[number];

/** Every P0 endpoint runs as SQL console's read-only role. */
const ENDPOINT_ROLES: readonly string[] = ["sql_console_read_only"];

/** Every P0 endpoint reads the system tables, so that is its database. */
const ENDPOINT_DATABASE = "system";

export type EndpointDefinition = {
  name: P0EndpointName;
  sql: string;
  /**
   * Default values for the endpoint's query parameters, by name. P0's
   * endpoints have none: a run sends each value it needs.
   */
  parameters: Record<string, string>;
};

// The databases P0 never lists: ClickHouse's own, and any whose name holds a
// `.`, since P0 splits a qualified name on its first one.
const HIDDEN_DATABASES = `database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') AND position(database, '.') = 0`;

/**
 * The most objects `objects` lists, and the most rows `p0_objects` returns
 * past it, so the lister can refuse rather than truncate. A count alone
 * doesn't keep the answer small: see {@link MAX_OBJECT_BYTES}.
 */
export const MAX_OBJECTS = 50_000;

/**
 * The most bytes `objects` answers with: each item counted as it travels,
 * `{"key":…,"value":…,"group":…}` and the comma between items. A Lambda's
 * answer can't pass 6 MB, so past 4 MiB the lister refuses too, which
 * leaves room for the array and the response around it.
 */
export const MAX_OBJECT_BYTES = 4 * 1024 * 1024;

/** P0's endpoints, by name. */
export const P0_ENDPOINTS: Readonly<
  Record<P0EndpointName, EndpointDefinition>
> = {
  // Every database, table, view, materialized view and dictionary, one row
  // each, as `{database, name, kind}`. A database's `name` is "".
  // Dictionaries also appear in `system.tables`, with engine `Dictionary`,
  // so they're read from `system.dictionaries` only. A materialized view's
  // hidden `.inner.` and `.inner_id.` tables aren't listed. The databases'
  // names are renamed in a subquery: in one `SELECT`, `'' AS name` would
  // stand for `name` in `name AS database` too. At most
  // `MAX_OBJECTS + 1` rows, so the lister can tell when there are too many.
  p0_objects: {
    name: "p0_objects",
    sql: [
      "SELECT database, name, kind FROM (",
      "SELECT database, '' AS name, 'database' AS kind FROM (SELECT name AS database FROM system.databases)",
      "UNION ALL",
      "SELECT database, name, multiIf(engine = 'View', 'view', engine = 'MaterializedView', 'materialized-view', 'table') AS kind FROM system.tables",
      "WHERE NOT is_temporary AND engine != 'Dictionary' AND NOT startsWith(name, '.inner.') AND NOT startsWith(name, '.inner_id.')",
      "UNION ALL",
      "SELECT database, name, 'dictionary' AS kind FROM system.dictionaries",
      `) WHERE ${HIDDEN_DATABASES}`,
      "ORDER BY database, name",
      `LIMIT ${MAX_OBJECTS + 1}`,
    ].join("\n"),
    parameters: {},
  },
};

/**
 * The request that creates or updates a P0 endpoint for the key: exactly
 * the definition, the read-only role, no CORS origins, and the key as the
 * only one allowed to run it.
 */
export const endpointRequest = (
  { name, sql, parameters }: EndpointDefinition,
  apiKeyUuid: string
): EndpointRequest => ({
  name,
  sql,
  database: ENDPOINT_DATABASE,
  parameters,
  apiKeyIds: [apiKeyUuid],
  roles: [...ENDPOINT_ROLES],
  allowedOrigins: [],
});

const sameIds = (actual: readonly string[], expected: readonly string[]) =>
  isEqual(
    actual.map((id) => id.toLowerCase()).sort(),
    expected.map((id) => id.toLowerCase()).sort()
  );

/**
 * Whether what a listing shows of an endpoint matches the definition for the
 * key. A listing leaves out the SQL and the parameters: see
 * {@link isCurrent}.
 */
export const matchesListed = (
  endpoint: ListedEndpoint,
  apiKeyUuid: string
): boolean =>
  endpoint.database === ENDPOINT_DATABASE &&
  isEqual([...endpoint.roles].sort(), [...ENDPOINT_ROLES].sort()) &&
  sameIds(endpoint.apiKeyIds, [apiKeyUuid]) &&
  endpoint.allowedOrigins.length === 0;

/** Whether an endpoint is exactly the definition for the key. */
export const isCurrent = (
  endpoint: ListedEndpoint & {
    parameters: Record<string, string>;
    sql: string;
  },
  definition: EndpointDefinition,
  apiKeyUuid: string
): boolean =>
  endpoint.name === definition.name &&
  matchesListed(endpoint, apiKeyUuid) &&
  endpoint.sql.trim() === definition.sql.trim() &&
  isEqual(endpoint.parameters, definition.parameters);
