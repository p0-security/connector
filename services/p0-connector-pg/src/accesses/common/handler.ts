import {
  type ConnectorContext,
  ConnectorError,
  type Logger,
} from "@p0security/connector";

import { newClient } from "../../dbclient.ts";
import { ident } from "../../sql/identifier.ts";
import type { PgClientParams, PgRequestContext } from "./definition.ts";

export type PgClient = Awaited<ReturnType<typeof newClient>>;

/** Whether a role with this name already exists in the database. */
export const roleExists = async (
  client: PgClient,
  username: string
): Promise<boolean> => {
  const res = await client.raw(
    "SELECT rolname FROM pg_roles WHERE rolname = ?",
    [username]
  );
  return res.rows.length > 0;
};

/**
 * Returns the names whose permissions the connector's own identity holds:
 * itself (`p0User` and the session user, since Cloud SQL connects as the
 * service account), and any role whose privileges it inherits or can
 * `SET ROLE` to. Granting a role to one of these would widen the connector's
 * own permissions. From PG16 a role's creator is an admin-only member of it,
 * so `MEMBER` is too broad there and only `USAGE` and `SET` count. A superuser
 * already holds every permission, so the membership check is skipped for it.
 */
const connectorRolesSql = `SELECT rolname FROM pg_roles
  WHERE rolname = ANY(?::text[])
    AND (
      rolname IN (current_user, session_user)
      OR (
        NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
        AND pg_has_role(current_user, oid,
          CASE WHEN current_setting('server_version_num')::int >= 160000
            THEN 'USAGE, SET' ELSE 'MEMBER' END)
      )
    )`;

/**
 * Rejects a grant to or from the connector's own identity, or to a role it
 * inherits. `p0_iam_manager` passes the `p0` prefix check, and on Cloud SQL
 * user names are not checked at all, so naming alone does not protect it.
 */
export const assertNotConnectorRole = async (
  client: PgClient,
  context: PgRequestContext,
  names: string[]
): Promise<void> => {
  const res = await client.raw<{ rows: { rolname: string }[] }>(
    connectorRolesSql,
    [names]
  );
  const reserved = [
    ...names.filter((name) => name === context.db.p0User),
    ...res.rows.map(({ rolname }) => rolname),
  ];
  if (reserved.length > 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid Postgres role: the connector's own identity",
      payload: { rolename: reserved[0] },
    });
  }
};

/** The roles a `role` policy may grant: non-login roles P0 did not create. */
const grantableRolesSql = `SELECT rolname FROM pg_roles
  WHERE NOT rolcanlogin AND rolname NOT ILIKE 'p0%'`;

/** Lists the roles a `role` policy may grant. */
export const listGrantableRoles = async (client: PgClient, logger: Logger) => {
  const res = await client.raw<{ rows: { rolname: string }[] }>(
    grantableRolesSql
  );
  logger.debug({ count: res.rows.length }, "listed Postgres roles");
  return res.rows.map(({ rolname }) => ({ key: rolname, value: rolname }));
};

/**
 * Rejects a `role` policy whose role `listGrantableRoles` would not offer, so a
 * request cannot grant the connector's role or another P0-managed one.
 */
export const assertGrantableRole = async (
  client: PgClient,
  rolename: string
): Promise<void> => {
  const res = await client.raw<{ rows: unknown[] }>(
    `${grantableRolesSql} AND rolname = ?`,
    [rolename]
  );
  if (res.rows.length === 0) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "Invalid Postgres role: only non-login roles that P0 did not create can be granted",
      payload: { rolename },
    });
  }
};

/** Lists the instance's databases */
export const listDatabases = async (client: PgClient, logger: Logger) => {
  const res = await client.raw<{ rows: { datname: string }[] }>(
    `SELECT datname FROM pg_database WHERE datistemplate = false`
  );
  logger.debug({ count: res.rows.length }, "listed Postgres databases");
  return res.rows.map(({ datname }) => ({ key: datname, value: datname }));
};

/**
 * Runs `handler` with a Postgres client and a logger scoped to the request's
 * database and the supplied fields.
 */
export const withMethodContext = async <O>(
  ctx: ConnectorContext,
  context: PgRequestContext,
  logFields: Record<string, unknown>,
  handler: (methodContext: { client: PgClient; logger: Logger }) => Promise<O>
): Promise<O> => {
  const { host, port } = context.db;
  const logger = ctx.logger.child({ host, port, ...logFields });
  return await withPgClient(context.db, logger, async (client) =>
    handler({ client, logger })
  );
};

/**
 * Runs `handler` against a Postgres client built from `params`, closing the
 * client afterwards.
 */
export const withPgClient = async <O>(
  params: PgClientParams,
  logger: Logger,
  handler: (client: PgClient) => Promise<O>
): Promise<O> => {
  const client = await newClient(
    {
      host: params.host,
      port: params.port,
      database: params.database,
      user: params.p0User,
    },
    params.cloud
  );

  try {
    return await handler(client);
  } finally {
    await client
      .destroy()
      .catch((error) =>
        logger.error({ error }, "failed to close Postgres client")
      );
  }
};

/**
 * The primitives that are identical across every Postgres access type: all of
 * them provision Postgres roles and bind them to each other. An access type
 * supplies only `addPolicyToResource`, `removePolicyFromResource` and `list`.
 */
export const newCommonPgPrimitives = (ctx: ConnectorContext) => ({
  /**
   * Marks users and resources as P0-managed by a `p0` name prefix. CloudSQL
   * users are skipped, as their names are fixed by the IAM principal's email.
   */
  validation: (context: PgRequestContext) => {
    const isP0Prefixed = async (name: string): Promise<boolean> =>
      Boolean(name.match(/^[pP]0/));

    const resource = {
      resourceIsNamespacedById: isP0Prefixed,
      resourceIsNamespacedByBody: isP0Prefixed,
    };

    const user = {
      userIsNamespacedById: isP0Prefixed,
      userIsNamespacedByBody: isP0Prefixed,
    };

    return {
      // in CloudSQL usernames are derived from IAM principal's email address
      user: context.db.cloud === "cloudsql" ? null : user,
      resource,
    };
  },

  /** Returns the username if a role by that name exists, otherwise null. */
  getUser: async (context: PgRequestContext, username: string) =>
    await withMethodContext(
      ctx,
      context,
      { username },
      async ({ client, logger }) => {
        const exists = await roleExists(client, username);
        logger.debug({ exists }, "checked whether Postgres user exists");
        return exists ? username : null;
      }
    ),

  /** Creates a login role for the user, if one does not already exist. */
  createUser: async (context: PgRequestContext, username: string) =>
    await withMethodContext(
      ctx,
      context,
      { username },
      async ({ client, logger }) => {
        if (!(await roleExists(client, username))) {
          await client.raw(`CREATE ROLE ${ident(username)} WITH LOGIN`);
          logger.info("created Postgres user");
        }
        return username;
      }
    ),

  /** Drops the user's role. */
  deleteUser: async (context: PgRequestContext, username: string) =>
    await withMethodContext(
      ctx,
      context,
      { username },
      async ({ client, logger }) => {
        await client.raw(`DROP ROLE IF EXISTS ${ident(username)}`);
        logger.info("dropped Postgres user");
      }
    ),

  /**
   * Creates the access resource's role, if it does not already exist. Unlike a
   * user's role, this one cannot log in; it only carries granted policies.
   */
  createResource: async (context: PgRequestContext, rolename: string) =>
    await withMethodContext(
      ctx,
      context,
      { rolename },
      async ({ client, logger }) => {
        await assertNotConnectorRole(client, context, [rolename]);
        if (!(await roleExists(client, rolename))) {
          await client.raw(`CREATE ROLE ${ident(rolename)}`);
          logger.info("created Postgres role");
        }
        return rolename;
      }
    ),

  /** Drops the access resource's role. */
  deleteResource: async (context: PgRequestContext, rolename: string) =>
    await withMethodContext(
      ctx,
      context,
      { rolename },
      async ({ client, logger }) => {
        await assertNotConnectorRole(client, context, [rolename]);
        await client.raw(`DROP ROLE IF EXISTS ${ident(rolename)}`);
        logger.info("dropped Postgres role");
      }
    ),

  /** Grants the access resource's role to the user, conferring its policies. */
  bindResourceToUser: async (
    context: PgRequestContext,
    rolename: string,
    username: string
  ) =>
    await withMethodContext(
      ctx,
      context,
      { rolename, username },
      async ({ client, logger }) => {
        await assertNotConnectorRole(client, context, [rolename, username]);
        await client.raw(`GRANT ${ident(rolename)} TO ${ident(username)}`);
        logger.info("granted Postgres role to user");
      }
    ),

  /** Revokes the access resource's role from the user. */
  unbindResourceFromUser: async (
    context: PgRequestContext,
    rolename: string,
    username: string
  ) =>
    await withMethodContext(
      ctx,
      context,
      { rolename, username },
      async ({ client, logger }) => {
        await assertNotConnectorRole(client, context, [rolename, username]);
        await client.raw(`REVOKE ${ident(rolename)} FROM ${ident(username)}`);
        logger.info("revoked Postgres role from user");
      }
    ),
});
