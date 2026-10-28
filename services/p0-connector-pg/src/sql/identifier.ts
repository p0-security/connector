import { ConnectorError } from "@p0security/connector-core";

// Postgres silently truncates longer identifiers, which could
// collapse two distinct principals onto the same role.
export const MAX_IDENTIFIER_BYTES = 63;

// Note that RFC-valid emails may include other characters as well
// In practice this should be rare as we can loosen this restriction later,
// but fail-closed using a character whitelist for now
const ALLOWED_IDENTIFIER_CHARACTERS_REGEX = /^[A-Za-z0-9._@+-]+$/;

const IDENTIFIER_GUARDS: readonly {
  reason: string;
  rejects: (name: string) => boolean;
}[] = [
  { reason: "must not be empty", rejects: (name) => name.length === 0 },
  {
    reason:
      "must contain only ASCII letters, digits, and the characters . _ @ + -",
    rejects: (name) => !ALLOWED_IDENTIFIER_CHARACTERS_REGEX.test(name),
  },
  {
    reason: `must be at most ${MAX_IDENTIFIER_BYTES} bytes`,
    rejects: (name) => Buffer.byteLength(name, "utf8") > MAX_IDENTIFIER_BYTES,
  },
];

export const ident = (name: string): string => {
  for (const guard of IDENTIFIER_GUARDS) {
    if (guard.rejects(name)) {
      throw new ConnectorError({
        type: "validation_error",
        message: `Invalid Postgres identifier: ${guard.reason}`,
        payload: { identifier: name },
      });
    }
  }
  return `"${name.replace(/"/g, '""')}"`;
};

/**
 * Normalizes a requested privilege to its SQL keyword and checks it against the
 * set of allowable privileges. Privileges cannot be bound as parameters, so the
 * keyword is interpolated into the statement and this check is what keeps that
 * safe.
 */
export const privilegeKeyword = (
  privilege: string,
  allowed: readonly string[]
): string => {
  // `ALL` is Postgres' shorthand for `ALL PRIVILEGES`.
  const keyword = privilege.trim().toUpperCase().replace(/\s+/g, " ");
  const canonical = keyword === "ALL" ? "ALL PRIVILEGES" : keyword;

  if (!allowed.includes(canonical)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `Unsupported Postgres privilege; expected one of: ${allowed.join(", ")}`,
      payload: { privilege },
    });
  }
  return canonical;
};

/**
 * Renders the qualified identifier naming a table-privilege target: a bare
 * `table`, or a `schema.table`.
 *
 * A target is always a concrete relation. SQL-text access derives its policies
 * from the tables a parsed query actually touches, so there is no request a
 * wildcard could express: `schema.*` is rejected rather than expanded to
 * `ON ALL TABLES IN SCHEMA`, which would grant far more than the query needed.
 */
export const tableIdent = (table: string): string => {
  // TODO: determine (and solve) any particular issues with regards to tables with dots in their names
  const parts = table.split(".");

  if (parts.some((part) => part.includes("*"))) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "Invalid Postgres table: wildcards are not supported; name a concrete `table` or `schema.table`",
      payload: { table },
    });
  }

  if (parts.length > 2 || parts.some((part) => part.length === 0)) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "Invalid Postgres table: expected a concrete `table` or `schema.table`",
      payload: { table },
    });
  }

  return parts.map((part) => ident(part)).join(".");
};
