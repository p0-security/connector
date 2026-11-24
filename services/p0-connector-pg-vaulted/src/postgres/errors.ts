import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";
import { z } from "zod";

type Failure = Pick<ConnectorErrorOptions, "message" | "type">;

const SIGN_IN_REFUSED: Failure = {
  type: "insufficient_privileges",
  message:
    "PostgreSQL refused the manager's sign-in. Check the username and password in the manager secret, and that the manager may connect to the target's database.",
};

const UNAVAILABLE: Failure = {
  type: "upstream_unavailable",
  message:
    "The connector could not reach PostgreSQL, or PostgreSQL did not answer in time. Check the network path from the connector to the target.",
};

const UNKNOWN: Failure = {
  type: "unknown",
  message:
    "PostgreSQL refused the operation for a reason the connector does not know. Contact P0 support.",
};

/**
 * What each PostgreSQL failure means to P0, by SQLSTATE, or else by SQLSTATE
 * class, which is its first two characters. The messages reach end users, so
 * none quotes the server's message or the statement.
 *
 * https://www.postgresql.org/docs/current/errcodes-appendix.html
 */
const FAILURES: Record<string, Failure> = {
  "28P01": SIGN_IN_REFUSED,
  "28000": SIGN_IN_REFUSED,
  "42501": {
    type: "insufficient_privileges",
    message:
      "PostgreSQL refused the operation because the manager lacks a privilege it needs.",
  },
  "42704": {
    type: "object_not_found",
    message: "A role the operation names does not exist in PostgreSQL.",
  },
  "3D000": {
    type: "object_not_found",
    message: "The target's database does not exist in PostgreSQL.",
  },
  "42710": {
    type: "already_exists",
    message: "A role with this name already exists in PostgreSQL.",
  },
  "2BP01": {
    type: "dependency_violation",
    message:
      "PostgreSQL refused the operation because other objects depend on the role.",
  },
  // A statement that waited longer for a lock than `lock_timeout`.
  "55P03": UNAVAILABLE,
  // Connection exceptions.
  "08": UNAVAILABLE,
  // Out of resources, such as connection slots.
  "53": UNAVAILABLE,
  // A shutdown, or a statement the statement timeout cancelled.
  "57": UNAVAILABLE,
};

/** An error the server answered with: the driver gives it the SQLSTATE as
 * `code`, and a `severity` that no network or TLS error has. */
const serverError = z.object({
  code: z.string().regex(/^[0-9A-Z]{5}$/),
  severity: z.string(),
});

/** A network or TLS error's code, such as `ECONNREFUSED`. */
const driverError = z.object({ code: z.string().regex(/^[A-Z][A-Z0-9_]*$/) });

/**
 * Maps what the driver threw to the error P0 shows, without its cause. The
 * driver's message quotes the statement, which is not for end users, so only
 * the SQLSTATE or the network error's code is kept, in the payload.
 *
 * An error without a SQLSTATE never got an answer from the server: the
 * connection failed, dropped or timed out.
 */
export const toConnectorError = (error: unknown): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const server = serverError.safeParse(error);
  if (server.success) {
    const sqlState = server.data.code;
    const failure =
      FAILURES[sqlState] ?? FAILURES[sqlState.slice(0, 2)] ?? UNKNOWN;
    return new ConnectorError({ ...failure, payload: { sqlState } });
  }
  const driver = driverError.safeParse(error);
  return new ConnectorError({
    ...UNAVAILABLE,
    payload: driver.success ? { code: driver.data.code } : {},
  });
};
