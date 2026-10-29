import { ConnectorError } from "@p0security/connector";

// The Data API takes parameters only as values, never as identifiers, and
// `CREATE USER`, `GRANT` and `ALTER … OWNER TO` name everything by
// identifier. So no statement uses parameters: every identifier is checked
// against a pattern and then quoted, and every string literal is escaped.
// Request input never reaches SQL any other way.

/**
 * A database, schema, table or role name. Redshift folds an unquoted name to
 * lower case; this connector quotes every name, so it keeps the case given.
 * At most 127 characters, as Redshift allows.
 */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]{0,126}$/;

/**
 * A database user name. Wider than {@link IDENTIFIER}: an IAM role signs in
 * as `IAMR:<role name>`, and a role name can hold `+=,.@-`.
 */
const USER_NAME = /^[A-Za-z0-9_][A-Za-z0-9_:+=,.@-]{0,126}$/;

/**
 * The agent's database user: `IAMR:p0-agent-<id>`, where `p0-agent-<id>` is
 * the per-grant IAM role. An IAM role name has at most 64 characters. P0
 * chooses the name; the connector only checks it, and acts on no user outside
 * this namespace.
 */
export const AGENT_USER_PATTERN = /^IAMR:p0-agent-[a-z0-9_-]{1,55}$/;

/** The grant's privilege role: `p0_agent_<id>`, with the same `<id>`. */
export const PRIVILEGE_ROLE_PATTERN = /^p0_agent_[a-z0-9_]{1,55}$/;

/** The role the install SQL gives the connector's user. */
export const CONNECTOR_ADMIN_ROLE = "p0_connector_admin";

export const isIdentifier = (value: string) => IDENTIFIER.test(value);

export const isUserName = (value: string) => USER_NAME.test(value);

const invalid = (what: string, value: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `Invalid Redshift ${what}`,
    payload: { [what]: value },
  });

/**
 * Quotes one name, after checking it against {@link IDENTIFIER}. The check
 * alone makes the result safe; the doubled `"` keeps it safe if the pattern
 * is ever widened.
 */
export const quoteIdentifier = (value: string) => {
  if (!isIdentifier(value)) throw invalid("identifier", value);
  return `"${value.replace(/"/g, '""')}"`;
};

/**
 * Quotes a name that Redshift returned, such as a table an agent created.
 * Redshift allows any character except NUL in a quoted name, so the name is
 * not checked against {@link IDENTIFIER}: a revoke must reach every object.
 */
export const quoteCatalogName = (value: string) => {
  if (value.length === 0 || value.includes("\0")) {
    throw invalid("identifier", value);
  }
  return `"${value.replace(/"/g, '""')}"`;
};

/**
 * The parts of `DB`, `DB.SCHEMA` or `DB.SCHEMA.TABLE`, or `undefined` when a
 * part is not an {@link IDENTIFIER}.
 */
export const objectNameParts = (value: string) => {
  const parts = value.split(".");
  return parts.length <= 3 && parts.every(isIdentifier) ? parts : undefined;
};

export const isObjectName = (value: string) =>
  objectNameParts(value) !== undefined;

/** Quotes a user name, after checking it against {@link USER_NAME}. */
export const quoteUserName = (value: string) => {
  if (!isUserName(value)) throw invalid("user", value);
  return `"${value.replace(/"/g, '""')}"`;
};

/**
 * A single-quoted string literal. Redshift reads `\` as an escape in a string
 * literal, so it is doubled along with `'`.
 */
export const quoteLiteral = (value: string) =>
  `'${value.replace(/\\/g, "\\\\").replace(/'/g, "''")}'`;

/** Refuses a user outside the agent namespace, before any SQL names it. */
export const assertAgentUser = (value: string) => {
  if (!AGENT_USER_PATTERN.test(value)) {
    throw new ConnectorError({
      type: "validation_error",
      message: "P0 acts only on users named IAMR:p0-agent-<id>",
      payload: { user: value },
    });
  }
  return value;
};

/** Refuses a role outside the privilege-role namespace. */
export const assertPrivilegeRole = (value: string) => {
  if (!PRIVILEGE_ROLE_PATTERN.test(value)) {
    throw new ConnectorError({
      type: "validation_error",
      message: "P0 acts only on roles named p0_agent_<id>",
      payload: { role: value },
    });
  }
  return value;
};
