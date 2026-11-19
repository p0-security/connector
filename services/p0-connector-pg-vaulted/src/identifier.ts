// copy of the identifier guards in services/p0-connector-pg/src/sql/identifier.ts
// Postgres silently truncates longer identifiers, which could collapse two
// distinct roles onto the same name.
const MAX_IDENTIFIER_BYTES = 63;

const ALLOWED_IDENTIFIER_CHARACTERS_REGEX = /^[A-Za-z0-9._@+-]+$/;

/** Whether `name` is a role name the connector will put into SQL. */
export const isIdentifier = (name: string) =>
  ALLOWED_IDENTIFIER_CHARACTERS_REGEX.test(name) &&
  Buffer.byteLength(name, "utf8") <= MAX_IDENTIFIER_BYTES;
