// Connection options and the execute wrapper are copied from
// app packages/integrations/snowflake/backend/src/client.ts. The pool is not:
// each operation opens one connection and destroys it when done.
import {
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
} from "@p0security/connector";
import { createPrivateKey } from "node:crypto";
import snowflake from "snowflake-sdk";

/**
 * Configures the SDK, once, on the first sign-in: the SDK's own logger off,
 * since it would write SQL text to `snowflake.log` and this connector logs
 * what it needs.
 *
 * OCSP stays at the SDK's fail-open default. Snowflake serves large results
 * from cloud storage whose certificates carry no OCSP responder, so
 * fail-closed checking rejects every listing past a few rows.
 *
 * Not at import: `snowflake.configure` is process-wide, and the P0 app shares
 * one `snowflake-sdk` with its Snowflake (HI) integration. The app imports
 * this package only through `./connector`, which never loads this file, but
 * configuring lazily keeps an import from ever changing the SDK for others.
 */
let configured = false;
const configureOnce = () => {
  if (configured) return;
  snowflake.configure({ logLevel: "OFF" });
  configured = true;
};

export type SnowflakeSignIn = {
  /** The account identifier, already checked against a closed pattern. */
  account: string;
  username: string;
  role: string;
  warehouse: string;
  /** An unencrypted PKCS8 PEM. */
  privateKey: string;
};

export type SnowflakeSession = {
  /** Runs a statement and discards any rows. Returns the query id. */
  execute: (sqlText: string) => Promise<string>;
  /** Runs a statement and returns its rows. */
  query: <T = Record<string, unknown>>(sqlText: string) => Promise<T[]>;
};

/** The first word or two of a statement, for logs: never its text, which may
 * name objects from the request. */
export const statementKind = (sqlText: string) =>
  sqlText.trim().split(/\s+/).slice(0, 2).join(" ").toUpperCase();

// Server error codes, from Snowflake's `SQL compilation error` messages.
const NOT_FOUND = new Set(["002003", "002043"]);
const ALREADY_EXISTS = new Set(["002002"]);
const INSUFFICIENT_PRIVILEGES = new Set(["003001"]);

/**
 * Maps a Snowflake error to the error P0 shows. The message is Snowflake's,
 * which names objects but never holds a token: no statement's text does.
 */
export const toConnectorError = (
  error: unknown,
  sqlText?: string
): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const { code, sqlState, message } = (error ?? {}) as snowflake.SnowflakeError;
  const serverCode = code === undefined ? undefined : String(code);
  const payload = {
    ...(serverCode ? { code: serverCode } : {}),
    ...(sqlState ? { sqlState } : {}),
    ...(sqlText ? { statement: statementKind(sqlText) } : {}),
  };
  return new ConnectorError({
    type: errorType(serverCode, sqlState),
    message: `Snowflake error: ${String(message ?? error)}`,
    payload,
  });
};

const errorType = (
  code: string | undefined,
  sqlState: string | undefined
): ConnectorErrorOptions["type"] => {
  // Not from Snowflake or its driver: a bug.
  if (!code) return "unknown";
  if (NOT_FOUND.has(code)) return "object_not_found";
  if (ALREADY_EXISTS.has(code)) return "already_exists";
  if (INSUFFICIENT_PRIVILEGES.has(code)) return "insufficient_privileges";
  // 390xxx: Snowflake refused the sign-in (key, user or role).
  if (code.startsWith("390")) return "insufficient_privileges";
  // A statement that reached Snowflake carries a SQL state. A driver error
  // without one (network, timeout) never reached it.
  return sqlState ? "unknown" : "upstream_unavailable";
};

/** The key as the SDK wants it. The error never quotes the key. */
export const exportPrivateKey = (pem: string) => {
  try {
    return createPrivateKey({ key: pem, format: "pem", type: "pkcs8" })
      .export({ format: "pem", type: "pkcs8" })
      .toString();
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The Snowflake connector private key must be an unencrypted PKCS8 PEM",
      payload: {},
    });
  }
};

const connect = (signIn: SnowflakeSignIn) => {
  configureOnce();
  const privateKey = exportPrivateKey(signIn.privateKey);
  return new Promise<snowflake.Connection>((resolve, reject) => {
    snowflake
      .createConnection({
        account: signIn.account,
        username: signIn.username,
        authenticator: "SNOWFLAKE_JWT",
        privateKey,
        role: signIn.role,
        warehouse: signIn.warehouse,
      })
      .connect((error, connection) =>
        error ? reject(toConnectorError(error)) : resolve(connection)
      );
  });
};

const run = (
  connection: snowflake.Connection,
  logger: Logger,
  sqlText: string
) =>
  new Promise<{ queryId: string; rows: unknown[] }>((resolve, reject) => {
    connection.execute({
      sqlText,
      complete: (error, statement, rows) => {
        if (error) {
          logger.error(
            {
              statement: statementKind(sqlText),
              code: error.code,
              sqlState: error.sqlState,
            },
            "Snowflake statement failed"
          );
          reject(toConnectorError(error, sqlText));
          return;
        }
        const queryId = statement.getQueryId();
        // Rows are never logged: an `ADD PROGRAMMATIC ACCESS TOKEN` row holds
        // the token.
        logger.debug(
          { statement: statementKind(sqlText), queryId },
          "Snowflake statement succeeded"
        );
        resolve({ queryId, rows: rows ?? [] });
      },
    });
  });

/**
 * Signs in to Snowflake, runs `use` with the session, and destroys the
 * connection when `use` settles.
 */
export const withSnowflake = async <T>(
  signIn: SnowflakeSignIn,
  logger: Logger,
  use: (session: SnowflakeSession) => Promise<T>
): Promise<T> => {
  const connection = await connect(signIn);
  const session: SnowflakeSession = {
    execute: async (sqlText) =>
      (await run(connection, logger, sqlText)).queryId,
    query: async <R>(sqlText: string) =>
      (await run(connection, logger, sqlText)).rows as R[],
  };
  try {
    return await use(session);
  } finally {
    connection.destroy((error) => {
      if (error)
        logger.warn(
          { code: error.code },
          "failed to close Snowflake connection"
        );
    });
  }
};
