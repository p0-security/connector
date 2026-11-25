import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";
import type { Knex } from "knex";
import { randomBytes } from "node:crypto";

import { installContext } from "../context.ts";
import { type ClientDependencies, newClient } from "../dbclient.ts";
import {
  CAN_CREATE_ROLE_SQL,
  CAN_SIGNAL_BACKEND_SQL,
  HAS_GRANT_OPTIONS_SQL,
  PING_SQL,
  type PgQuery,
  grantableRoles,
  holds,
  reassignOwnedStatements,
} from "../postgres/catalog.ts";
import { toConnectorError } from "../postgres/errors.ts";
import { ident } from "../sql/identifier.ts";
import type { InstallValidation, PgVaultedInstallStep } from "./definition.ts";

// copy of `at` in services/p0-connector-snowflake-ai/src/install/handler.ts
/**
 * Runs `run` as `step`: its failure is thrown as a `ConnectorError` that
 * carries the step and the target's host. A failure that already names a
 * step keeps it.
 */
const at = async <T>(
  step: PgVaultedInstallStep,
  host: string,
  run: () => Promise<T>
): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    if (!(error instanceof ConnectorError) || "step" in error.data.payload) {
      throw error;
    }
    throw new ConnectorError({
      ...error.data,
      payload: { ...error.data.payload, step, host },
    });
  }
};

/** Runs `runner`'s statements. A failure is thrown as the `ConnectorError`
 * {@link toConnectorError} maps it to. */
const queryOn =
  (runner: Pick<Knex, "raw">): PgQuery =>
  async (sql) => {
    try {
      return (await runner.raw<{ rows: unknown[] }>(sql)).rows;
    } catch (error) {
      throw toConnectorError(error);
    }
  };

/** Runs `run` in one transaction, which is rolled back however `run` ends,
 * so nothing `run` did stays. */
const rolledBack = async <T>(
  client: Knex,
  logger: Logger,
  run: (query: PgQuery) => Promise<T>
): Promise<T> => {
  const transaction = await client.transaction().catch((error: unknown) => {
    throw toConnectorError(error);
  });
  try {
    return await run(queryOn(transaction));
  } finally {
    // A rollback that fails still leaves nothing behind: PostgreSQL drops an
    // open transaction when its connection closes, which happens next.
    await transaction
      .rollback()
      .catch((error: unknown) =>
        logger.error(
          { failure: toConnectorError(error).data },
          "failed to roll back the PostgreSQL transaction"
        )
      );
  }
};

/** The checks that one yes-or-no statement answers, in order. */
const PRIVILEGE_CHECKS: {
  step: PgVaultedInstallStep;
  sql: string;
  message: string;
}[] = [
  {
    step: "create_role",
    sql: CAN_CREATE_ROLE_SQL,
    message: "The manager cannot create roles. Give it CREATEROLE.",
  },
  {
    step: "signal_backend",
    sql: CAN_SIGNAL_BACKEND_SQL,
    message:
      "The manager cannot end other logins' sessions. Grant it pg_signal_backend.",
  },
];

/**
 * The checks after the manager secret, in order. The client connects on its
 * first statement, so that statement's failure is the sign-in's, which the
 * caller names.
 */
const checkManager = async (
  client: Knex,
  logger: Logger,
  host: string
): Promise<InstallValidation> => {
  const query = queryOn(client);
  await query(PING_SQL);

  for (const { step, sql, message } of PRIVILEGE_CHECKS) {
    if (!(await at(step, host, () => holds(query, sql)))) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message,
        payload: { step, host },
      });
    }
  }

  return at("reassign_owned", host, async () => {
    const roles = await grantableRoles(query);
    const hasGrantOptions = await holds(query, HAS_GRANT_OPTIONS_SQL);
    await rolledBack(client, logger, async (inTransaction) => {
      // Named like a grant login, so the probe meets whatever a grant login
      // would.
      const probe = `p0v_${randomBytes(16).toString("hex")}`;
      await inTransaction(`CREATE ROLE ${ident(probe)} NOLOGIN`);
      const [owner] = roles;
      if (owner === undefined) return;
      for (const statement of reassignOwnedStatements(
        probe,
        owner,
        hasGrantOptions
      )) {
        await inTransaction(statement);
      }
    });
    return { grantableRoles: roles };
  });
};

/**
 * Lets the installer confirm the connector can manage a target. `get` runs
 * the checks of `PG_VAULTED_INSTALL_STEPS` in order and stops at the first
 * that fails. It leaves nothing behind: its only writes are in a transaction
 * that is rolled back.
 */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: ClientDependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);

  return t.router({
    get: procedure
      .input(installContext.parse)
      .query(async ({ input, ctx }): Promise<InstallValidation> => {
        const { target } = input;
        const { host, port, database } = target;
        const logger = ctx.logger.child({ host, port, database });
        const client = await at("manager_secret", host, () =>
          newClient(target, "rds", dependencies)
        );
        try {
          const validation = await at("sign_in", host, () =>
            checkManager(client, logger, host)
          );
          logger.info(
            { nGrantableRoles: validation.grantableRoles.length },
            "validated the PostgreSQL target"
          );
          return validation;
        } finally {
          await client
            .destroy()
            .catch((error: unknown) =>
              logger.error(
                { failure: toConnectorError(error).data },
                "failed to close the PostgreSQL client"
              )
            );
        }
      }),
  });
};
