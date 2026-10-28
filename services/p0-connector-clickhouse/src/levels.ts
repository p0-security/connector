import { ConnectorError } from "@p0security/connector";

import { quoteIdentifier, quoteTable } from "./query/identifiers.ts";

/**
 * The levels a `sql` request asks for, and the GRANT statements each one
 * becomes in a ClickHouse Cloud custom role's `tags.grants`.
 */

/** Every level, from least to most. */
export const LEVELS = ["read", "write", "admin"] as const;

export type Level = (typeof LEVELS)[number];

const READ = ["SELECT", "dictGet"] as const;

const WRITE = [
  ...READ,
  "INSERT",
  "ALTER UPDATE",
  "ALTER DELETE",
  "TRUNCATE",
] as const;

const ADMIN = [...WRITE, "CREATE", "DROP", "ALTER", "OPTIMIZE"] as const;

/**
 * The privileges each level grants, each level holding every privilege of
 * the one below it. No level holds `ACCESS MANAGEMENT`, `GRANT OPTION`,
 * `SYSTEM`, `KILL QUERY`, named collections or `SOURCES`.
 *
 * The app keeps its own copy, for the approval text, and pins it to this one
 * in a test.
 */
export const LEVEL_PRIVILEGES: {
  readonly [L in Level]: readonly string[];
} = { read: READ, write: WRITE, admin: ADMIN };

/**
 * What a `sql` request is on: the whole service (`{}`), one database
 * (`{database}`), or one table, view, materialized view or dictionary
 * (`{database, table}`).
 */
export type GrantObject = { database?: string; table?: string };

/** Where a GRANT applies: `*.*`, `` `db`.* `` or `` `db`.`table` ``. */
const targetOf = ({ database, table }: GrantObject): string => {
  if (database === undefined) {
    if (table !== undefined) {
      throw new ConnectorError({
        type: "validation_error",
        message: "A sql request names a table without its database.",
        payload: {},
      });
    }
    return "*.*";
  }
  return table === undefined
    ? `${quoteIdentifier(database)}.*`
    : quoteTable({ database, table });
};

/**
 * On the whole service, `write` and `admin` take back on `system.*` every
 * privilege beyond `read`'s, as a partial revoke: otherwise the grantee
 * could delete or truncate ClickHouse's logs (`system.query_log`,
 * `system.session_log`), the evidence of what they did with the grant.
 */
const systemRevoke = (level: Level, object: GrantObject): string[] => {
  if (object.database !== undefined) return [];
  const beyondRead = LEVEL_PRIVILEGES[level].filter(
    (privilege) => !LEVEL_PRIVILEGES.read.includes(privilege)
  );
  return beyondRead.length === 0
    ? []
    : [`REVOKE ${beyondRead.join(", ")} ON ${quoteIdentifier("system")}.*`];
};

/**
 * The GRANT statements for a `sql` request, one per element of
 * `tags.grants`: the level's privileges on the object. On the whole service
 * at `write` or `admin`, a last element revokes what's beyond `read` on
 * `system.*`.
 *
 * Every name is backtick-quoted, with backslashes and backticks escaped, so
 * no name can end the statement or start another.
 */
export const levelGrants = ({
  level,
  object,
}: {
  level: Level;
  object: GrantObject;
}): string[] => [
  `GRANT ${LEVEL_PRIVILEGES[level].join(", ")} ON ${targetOf(object)}`,
  ...systemRevoke(level, object),
];
