import { ConnectorError } from "@p0security/connector-core";

// copy of the identifier guards in services/p0-connector-pg/src/sql/identifier.ts
// Postgres silently truncates longer identifiers, which could collapse two
// distinct roles onto the same name.
const MAX_IDENTIFIER_BYTES = 63;

const ALLOWED_IDENTIFIER_CHARACTERS_REGEX = /^[A-Za-z0-9._@+-]+$/;

/** Whether `name` is a role name the connector will put into SQL. */
export const isIdentifier = (name: string) =>
  ALLOWED_IDENTIFIER_CHARACTERS_REGEX.test(name) &&
  Buffer.byteLength(name, "utf8") <= MAX_IDENTIFIER_BYTES;

/**
 * `name` as a quoted identifier, for the statements that take no bindings.
 * It refuses any name {@link isIdentifier} refuses, so a name that reaches
 * SQL holds no quote to escape.
 */
export const ident = (name: string): string => {
  if (!isIdentifier(name)) {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid PostgreSQL role name",
      payload: {},
    });
  }
  return `"${name}"`;
};
