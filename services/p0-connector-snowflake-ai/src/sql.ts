import { ConnectorError } from "@p0security/connector-core";

// Snowflake does not take binds in every DDL statement this connector runs
// (`CREATE USER`, `GRANT … TO ROLE`, `ALTER USER … ADD PROGRAMMATIC ACCESS
// TOKEN`, `SHOW … LIKE`). So no statement uses binds: every identifier is
// checked against a strict pattern and then quoted, and every string literal
// is escaped. Request input never reaches SQL any other way.

/**
 * One part of an object name. The characters of an unquoted Snowflake
 * identifier, in any case: the name is quoted, so its case is kept as given.
 */
const IDENTIFIER_PART = /^[A-Za-z_][A-Za-z0-9_$]{0,254}$/;

/** `DB`, `DB.SCHEMA` or `DB.SCHEMA.OBJECT`. */
const OBJECT_NAME =
  /^[A-Za-z_][A-Za-z0-9_$]{0,254}(\.[A-Za-z_][A-Za-z0-9_$]{0,254}){0,2}$/;

export const isIdentifierPart = (value: string) => IDENTIFIER_PART.test(value);

export const isObjectName = (value: string) => OBJECT_NAME.test(value);

const invalidIdentifier = (value: string) =>
  new ConnectorError({
    type: "validation_error",
    message: "Invalid Snowflake identifier",
    payload: { identifier: value },
  });

/**
 * Quotes one identifier part, after checking it against
 * {@link IDENTIFIER_PART}. The check alone makes the result safe; the doubled
 * `"` keeps it safe if the pattern is ever widened.
 */
export const quoteIdentifier = (value: string) => {
  if (!isIdentifierPart(value)) throw invalidIdentifier(value);
  return `"${value.replace(/"/g, '""')}"`;
};

/** Splits a dotted object name into its parts, after checking it. */
export const objectNameParts = (value: string) => {
  if (!isObjectName(value)) throw invalidIdentifier(value);
  return value.split(".");
};

/** Quotes a dotted object name part by part: `"DB"."SCHEMA"."TABLE"`. */
export const quoteObjectName = (value: string) =>
  objectNameParts(value).map(quoteIdentifier).join(".");

/**
 * A single-quoted string literal. Snowflake treats `\` as an escape in
 * single-quoted strings, so it is doubled along with `'`.
 */
export const quoteLiteral = (value: string) =>
  `'${value.replace(/\\/g, "\\\\").replace(/'/g, "''")}'`;
