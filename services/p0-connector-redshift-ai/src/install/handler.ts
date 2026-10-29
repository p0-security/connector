import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { type InstallContext, installContext } from "../context.ts";
import {
  type DataApiDependencies,
  type RedshiftSession,
  newRedshiftSession,
  toConnectorError,
} from "../redshift/data-api.ts";
import { localDatabases } from "../redshift/databases.ts";
import {
  type TargetLookupDependencies,
  lookupTargetArn,
} from "../redshift/target.ts";
import { quoteIdentifier, quoteLiteral } from "../sql.ts";
import type {
  InstallValidation,
  InstallWarning,
  RedshiftAiInstallStep,
} from "./definition.ts";

/**
 * The system permissions revoke needs: `ALTER TABLE` hands an agent's
 * tables, views and materialized views over, and the `DROP` permissions
 * remove its functions, procedures and empty schemas, whose owner only a
 * superuser can change.
 */
export const REQUIRED_SYSTEM_PERMISSIONS = [
  "ALTER TABLE",
  "DROP SCHEMA",
  "DROP FUNCTION",
  "DROP PROCEDURE",
] as const;

const SECADMIN_ROLE = "sys:secadmin";

/**
 * Runs `run` as `step`: its failure is thrown as a `ConnectorError` that
 * carries the step and the target. A failure that already names a step
 * keeps it.
 */
const at = async <T>(
  step: RedshiftAiInstallStep,
  target: string,
  run: () => Promise<T>
): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    const { data } = toConnectorError(error);
    if ("step" in data.payload) throw error;
    throw new ConnectorError({
      ...data,
      payload: { ...data.payload, step, target },
    });
  }
};

const failed = (
  step: RedshiftAiInstallStep,
  target: string,
  type: ConnectorErrorOptions["type"],
  message: string
) => new ConnectorError({ type, message, payload: { step, target } });

/**
 * Whether the connector's user may run revoke: a superuser, or a member of
 * `sys:secadmin` that holds every {@link REQUIRED_SYSTEM_PERMISSIONS}, itself
 * or through a role granted to it directly. Nested roles aren't followed.
 */
const checkAdminRoles = async (
  session: RedshiftSession,
  install: InstallContext,
  user: string
) => {
  const target = install.target.name;
  const [self] = await session.query<{ usesuper: boolean }>(
    "SELECT usesuper FROM pg_user WHERE usename = current_user"
  );
  if (self?.usesuper) return { superuser: true };

  const roles = (
    await session.query<{ role_name: string }>(
      "SELECT role_name FROM svv_user_grants WHERE user_name = current_user"
    )
  ).map(({ role_name }) => role_name);
  if (!roles.includes(SECADMIN_ROLE)) {
    throw failed(
      "admin_roles",
      target,
      "insufficient_privileges",
      `The connector's user ${user} must be granted the ${SECADMIN_ROLE} role`
    );
  }

  const identities = [user, ...roles].map(quoteLiteral).join(", ");
  const held = new Set(
    (
      await session.query<{ system_privilege: string }>(
        `SELECT system_privilege FROM svv_system_privileges WHERE identity_name IN (${identities})`
      )
    ).map(({ system_privilege }) => system_privilege.toUpperCase())
  );
  const missing = REQUIRED_SYSTEM_PERMISSIONS.filter((name) => !held.has(name));
  if (missing.length > 0) {
    throw failed(
      "admin_roles",
      target,
      "insufficient_privileges",
      `The connector's user ${user} must hold the ${missing.join(", ")} system permissions`
    );
  }
  return { superuser: false };
};

const checkObjectOwner = async (
  session: RedshiftSession,
  install: InstallContext
) => {
  const { objectOwner, target } = install;
  if (objectOwner === undefined) return;
  const users = await session.query(
    `SELECT usename FROM pg_user WHERE usename = ${quoteLiteral(objectOwner)}`
  );
  if (users.length === 0) {
    throw failed(
      "object_owner",
      target.name,
      "object_not_found",
      `The object owner ${objectOwner} is not a user in Redshift ${target.name}`
    );
  }
};

/** Whether the connector's user owns, or can grant, any table or view in
 * the install's database. */
const hasGrantableObjects = async (session: RedshiftSession) => {
  const [withGrantOption] = await session.query<{ n: number }>(
    "SELECT count(*) AS n FROM svv_relation_privileges WHERE identity_name = current_user AND admin_option"
  );
  if ((withGrantOption?.n ?? 0) > 0) return true;
  const [owned] = await session.query<{ n: number }>(
    "SELECT count(*) AS n FROM (SELECT tablename FROM pg_tables WHERE tableowner = current_user UNION ALL SELECT viewname FROM pg_views WHERE viewowner = current_user)"
  );
  return (owned?.n ?? 0) > 0;
};

/**
 * Whether a `SHOW SCHEMAS` ACL lets PUBLIC create: its entries are
 * `~`-separated `grantee=privileges/grantor`, and PUBLIC's grantee is empty.
 */
export const publicCanCreate = (acl: string | null | undefined) =>
  (acl ?? "")
    .split("~")
    .some(
      (entry) =>
        entry.startsWith("=") && entry.slice(1).split("/")[0]!.includes("C")
    );

/** The local databases where PUBLIC can still create in `public`. */
const publicCreateDatabases = async (
  session: RedshiftSession,
  logger: Logger
) => {
  const found: string[] = [];
  for (const database_name of await localDatabases(session, logger)) {
    const schemas = await session.query<{
      schema_name: string;
      schema_acl: string | null;
    }>(`SHOW SCHEMAS FROM DATABASE ${quoteIdentifier(database_name)};`);
    const publicSchema = schemas.find(
      ({ schema_name }) => schema_name === "public"
    );
    if (publicSchema && publicCanCreate(publicSchema.schema_acl)) {
      found.push(database_name);
    }
  }
  return found;
};

export type InstallDependencies = DataApiDependencies &
  TargetLookupDependencies;

/** Every check, in order. */
export const validateInstall = async (
  install: InstallContext,
  logger: Logger,
  dependencies: InstallDependencies = {}
): Promise<InstallValidation> => {
  const target = install.target.name;
  const arn = await at("target", target, () =>
    lookupTargetArn(install, dependencies)
  );
  const session = newRedshiftSession(install, logger, dependencies);

  const [identity] = await at("sign_in", target, () =>
    session.query<{ user_name: string }>("SELECT current_user AS user_name")
  );
  if (!identity) {
    throw failed("sign_in", target, "unknown", "Redshift returned no user");
  }
  const user = identity.user_name;

  const { superuser } = await at("admin_roles", target, () =>
    checkAdminRoles(session, install, user)
  );
  await at("object_owner", target, () => checkObjectOwner(session, install));

  const warnings: InstallWarning[] = [];
  if (!superuser && !(await hasGrantableObjects(session))) {
    warnings.push({ check: "grantable_objects", database: install.database });
  }
  for (const database of await publicCreateDatabases(session, logger)) {
    warnings.push({ check: "public_create", database });
  }
  return { arn, user, warnings };
};

/**
 * Lets the installer confirm the connector can act on a cluster or
 * workgroup. `get` is what install validation runs, every hour, so it never
 * writes.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(installContext.parse)
      .query(async ({ input, ctx }): Promise<InstallValidation> => {
        const logger = ctx.logger.child({
          target: input.target.name,
          targetType: input.target.type,
          region: input.region,
        });
        const validation = await validateInstall(input, logger);
        logger.info(
          { user: validation.user, warnings: validation.warnings },
          "validated the Redshift install"
        );
        return validation;
      }),
  });
};
