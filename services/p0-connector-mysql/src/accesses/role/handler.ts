import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type Logger,
  newResourceHierarchyRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import type { Knex } from "knex";
import type { z } from "zod";

import type { Cloud } from "../../clouds/index.ts";
import { newClient } from "../../dbclient.ts";
import type { schema } from "./definition.ts";
import { spec } from "./definition.ts";

type DefaultRole = {
  default_role_user: string;
  default_role_host: string;
};
type DefaultRoleRow = DefaultRole & { host: string; user: string };

const ANY_HOST = "%";

// Returns both role user and host, in case there are non-P0-managed default roles with hosts
// assigned to the user outside of P0
const getDefaultRolesForUser = async (
  knex: Knex,
  user: string
): Promise<DefaultRole[]> =>
  await knex<DefaultRoleRow>("mysql.default_roles")
    // While it is unlikely that there's another 'p0_first_last' user defined on another host,
    // we defend against that by filtering host to ANY_HOST here
    .where({ user, host: ANY_HOST })
    .select("default_role_user", "default_role_host");

const setDefaultRolesForUser = async (
  knex: Knex,
  user: string,
  defaultRoles: DefaultRole[]
): Promise<void> => {
  await knex.raw(
    `SET DEFAULT ROLE ${defaultRoles.map(() => "??@??").join(", ")} TO ??`,
    [
      ...defaultRoles.flatMap((r) => [
        r.default_role_user,
        r.default_role_host,
      ]),
      user,
    ]
  );
};

const roleExists = async (
  client: Awaited<ReturnType<typeof newClient>>,
  role: string
): Promise<boolean> => {
  const res = await client.raw("SELECT User FROM mysql.user WHERE User = ?", [
    role,
  ]);
  return res[0].length > 0;
};

const withMethodContext = async <O>(
  context: z.infer<(typeof schema)["requestContext"]>,
  logger: Logger,
  handler: (methodContext: {
    client: Awaited<ReturnType<typeof newClient>>;
    cloud: Cloud;
  }) => Promise<O>
) => {
  const cloud = context.db.cloud;
  const client = await newClient(
    {
      user: context.db.p0User,
      host: context.db.host,
      port: context.db.port,
    },
    cloud
  );

  try {
    return await handler({ client, cloud });
  } finally {
    client
      .destroy()
      .catch((error) =>
        logger.error({ error }, "failed to close MySQL client")
      );
  }
};

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceHierarchyRouter(t, spec, (ctx: ConnectorContext) => {
    return {
      validation(context) {
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

      async getUser(context, username) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, username });
        return await withMethodContext(context, logger, async ({ client }) => {
          const exists = await roleExists(client, username);
          logger.debug({ exists }, "checked whether MySQL user exists");
          return exists ? username : null;
        });
      },

      async createUser(context, user) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, user });
        return await withMethodContext(
          context,
          logger,
          async ({ client, cloud }) => {
            if (!(await roleExists(client, user))) {
              await client.raw(`CREATE USER ??`, [user]);
              logger.info("created MySQL user");
            }

            switch (cloud) {
              case "rds": {
                await client.raw(
                  `ALTER USER ?? IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'`,
                  [user]
                );
                break;
              }
              case "cloudsql":
              case "localhost":
                break;
              default:
                throw throwAssertNever(cloud);
            }

            return user;
          }
        );
      },

      async deleteUser(context, user) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, user });
        return await withMethodContext(context, logger, async ({ client }) => {
          await client.raw(`DROP USER IF EXISTS ??`, [user]);
          logger.info("dropped MySQL user");
        });
      },

      async createResource(context, rolename) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, rolename });
        return await withMethodContext(context, logger, async ({ client }) => {
          // hoist up a level to getResource? to avoid having implementers rewrite this logic again and again?
          if (!(await roleExists(client, rolename))) {
            await client.raw(`CREATE ROLE ??`, [rolename]);
            logger.info("created MySQL role");
          }
          return rolename;
        });
      },

      async deleteResource(context, rolename) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, rolename });
        return await withMethodContext(context, logger, async ({ client }) => {
          await client.raw(`DROP ROLE IF EXISTS ??`, [rolename]);
          logger.info("dropped MySQL role");
        });
      },

      async bindResourceToUser(context, rolename, user) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, rolename, user });
        return await withMethodContext(context, logger, async ({ client }) => {
          await client.transaction(async (tx) => {
            const defaultRoles = await getDefaultRolesForUser(tx, user);
            await tx.raw("GRANT ?? TO ??", [rolename, user]);
            await setDefaultRolesForUser(tx, user, [
              ...defaultRoles,
              { default_role_user: rolename, default_role_host: ANY_HOST },
            ]);
            await tx.commit();
          });
          logger.info("granted MySQL role to user");
        });
      },

      async unbindResourceFromUser(context, rolename, user) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({ host, port, rolename, user });
        return await withMethodContext(context, logger, async ({ client }) => {
          // No need to update DEFAULT ROLES as that is automatically handled by MySQL
          await client.raw("REVOKE ?? FROM ??", [rolename, user]);
          logger.info("revoked MySQL role from user");
        });
      },

      async addPolicyToResource(context, resourceBody, policy) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({
          host,
          port,
          resourceBody,
          policy,
        });
        return await withMethodContext(context, logger, async ({ client }) => {
          const type = policy.type;
          switch (type) {
            case "role": {
              const params = [policy.rolename, resourceBody];
              await client.raw(`GRANT ?? TO ??`, params);
              break;
            }
            case "schema-privilege": {
              const params = [policy.schema, resourceBody];
              await client.raw(
                `GRANT ${policy.privilege} ON ??.* TO ??`,
                params
              );
              break;
            }
            case "table-privilege": {
              const params = [policy.schema, policy.table, resourceBody];
              await client.raw(
                `GRANT ${policy.privilege} ON ??.?? TO ??`,
                params
              );
              break;
            }
            default: {
              throw throwAssertNever(type);
            }
          }
          logger.info("granted policy to MySQL resource");
        });
      },

      async removePolicyFromResource(context, resourceBody, policy) {
        const { host, port } = context.db;
        const logger = ctx.logger.child({
          host,
          port,
          resourceBody,
          policy,
        });
        return await withMethodContext(context, logger, async ({ client }) => {
          const type = policy.type;
          switch (type) {
            case "role": {
              const params = [policy.rolename, resourceBody];
              await client.raw(`REVOKE ?? FROM ??`, params);
              break;
            }
            case "schema-privilege": {
              const params = [policy.schema, resourceBody];
              await client.raw(
                `REVOKE ${policy.privilege} ON ??.* FROM ??`,
                params
              );
              break;
            }
            case "table-privilege": {
              const params = [policy.schema, policy.table, resourceBody];
              await client.raw(
                `REVOKE ${policy.privilege} ON ??.?? FROM ??`,
                params
              );
              break;
            }
            default: {
              throw throwAssertNever(type);
            }
          }
          logger.info("revoked policy from MySQL resource");
        });
      },

      async list({ type, context }) {
        const { host, port } = context;
        const logger = ctx.logger.child({ host, port, type });
        const client = await newClient(
          {
            user: context.p0User,
            host: context.host,
            port: context.port,
          },
          context.cloud
        );

        try {
          switch (type) {
            case "database": {
              const [res] = await client.raw<[{ SCHEMA_NAME: string }[]]>(
                `SELECT SCHEMA_NAME FROM information_schema.SCHEMATA`
              );

              logger.debug({ count: res.length }, "listed MySQL databases");
              return res.map(({ SCHEMA_NAME }) => ({
                key: SCHEMA_NAME,
                value: SCHEMA_NAME,
              }));
            }
            case "role": {
              const [res] = await client.raw<[{ User: string }[]]>(
                // MySQL doesn't have separate concepts for users and roles,
                // so use account_locked as a close-enough proxy for whether something is a user or a role
                `SELECT User FROM mysql.user WHERE User NOT LIKE ? AND User NOT LIKE ? AND account_locked = 'Y'`,
                ["P0%", "p0%"]
              );

              logger.debug({ count: res.length }, "listed MySQL roles");
              return res.map(({ User }) => ({ key: User, value: User }));
            }
            default:
              throw throwAssertNever(type);
          }
        } finally {
          client
            .destroy()
            .catch((error) =>
              logger.error({ error }, "failed to close MySQL client")
            );
        }
      },
    };
  });
