import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  withRouteLogging,
} from "@p0security/connector-core";
import { randomBytes } from "node:crypto";

import { installContext } from "../context.ts";
import type { Dependencies } from "../dependencies.ts";
import { readManagerCredential, withManager } from "../manager.ts";
import {
  CAN_CREATE_ROLE_SQL,
  CAN_SIGNAL_BACKEND_SQL,
  HAS_GRANT_OPTIONS_SQL,
  PING_SQL,
  holds,
  listGrantableRoles,
  reassignOwnedStatement,
  takePrivilegesStatement,
} from "../postgres/catalog.ts";
import type { PgSession } from "../postgres/client.ts";
import { execute } from "../postgres/statement.ts";
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
 * The checks inside the session, in order. The first statement is where the
 * driver connects, so its failure is the sign-in's, which the caller names.
 */
const checkManager = async (
  { query, rolledBack }: PgSession,
  host: string
): Promise<InstallValidation> => {
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
    const grantableRoles = await listGrantableRoles(query);
    const hasGrantOptions = await holds(query, HAS_GRANT_OPTIONS_SQL);
    await rolledBack(async (inTransaction) => {
      // Named like a grant login, so the probe meets whatever a grant login
      // would.
      const probe = `p0v_${randomBytes(16).toString("hex")}`;
      await execute(inTransaction, {
        template: "CREATE ROLE %I NOLOGIN",
        args: [probe],
      });
      const [owner] = grantableRoles;
      if (owner === undefined) return;
      await execute(
        inTransaction,
        takePrivilegesStatement(probe, hasGrantOptions)
      );
      await execute(inTransaction, reassignOwnedStatement(probe, owner));
    });
    return { grantableRoles };
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
  dependencies: Dependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);

  return t.router({
    get: procedure
      .input(installContext.parse)
      .query(async ({ input, ctx }): Promise<InstallValidation> => {
        const { target } = input;
        const { host, port, database } = target;
        const scope = ctx.logger.child({ host, port });
        const logger = scope.child({ database });
        const credential = await at("manager_secret", host, () =>
          readManagerCredential(target, dependencies)
        );
        const validation = await at("sign_in", host, () =>
          withManager(target, credential, dependencies, scope, (session) =>
            checkManager(session, host)
          )
        );
        logger.info(
          { nGrantableRoles: validation.grantableRoles.length },
          "validated the PostgreSQL target"
        );
        return validation;
      }),
  });
};
